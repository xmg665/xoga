//go:build unix

package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/dns"
)

func startMockDualStackDNS(t *testing.T, v4s [][4]byte, v6s [][16]byte) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if n < 16 {
				continue
			}
			qtype := binary.BigEndian.Uint16(buf[n-4 : n-2])
			resp := make([]byte, 0, n+128)
			resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01)
			if qtype == 1 && len(v4s) > 0 {
				resp = append(resp, 0x00, byte(len(v4s)), 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
				for _, ip := range v4s {
					resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
					resp = append(resp, ip[:]...)
				}
			} else if qtype == 28 && len(v6s) > 0 {
				resp = append(resp, 0x00, byte(len(v6s)), 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
				for _, ip := range v6s {
					resp = append(resp, 0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10)
					resp = append(resp, ip[:]...)
				}
			} else {
				resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func TestBUG3IPv4ErrorPrecedenceBudgetAndIPv6Fallback(t *testing.T) {
	v6IP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// 1. Mixed candidates [v4_1, v6_1] inside dialCandidateAddrs:
	//    v4 fails with ECONNREFUSED; trailing v6 fails with ENETUNREACH or os.ErrDeadlineExceeded ->
	//    MUST return v4 ECONNREFUSED in both cases (never clobbered by tcp6 unreachable/timeout).
	for _, tc := range []struct {
		name  string
		v6Err error
	}{
		{"V6_ENETUNREACH", &net.OpError{Op: "dial", Net: "tcp6", Err: syscall.ENETUNREACH}},
		{"V6_OsDeadlineExceeded", &net.OpError{Op: "dial", Net: "tcp6", Err: os.ErrDeadlineExceeded}},
		{"V6_ContextDeadlineExceeded", context.DeadlineExceeded},
	} {
		t.Run("MixedV4Then"+tc.name, func(t *testing.T) {
			cands := []netip.Addr{
				netip.MustParseAddr("198.51.100.1"),
				netip.MustParseAddr("2001:db8::1"),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := dialCandidateAddrs(
				ctx,
				cands,
				443,
				acl.OutboundNode{Type: "direct"},
				acl.OutboundTarget{Action: acl.ActionDirect},
				3*time.Second,
				func(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
					if network == "tcp4" {
						return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ECONNREFUSED}
					}
					return nil, tc.v6Err
				},
			)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("expected IPv4 ECONNREFUSED to be preserved over %s, got %v", tc.name, err)
			}
		})
	}

	// 2. Fair budget division + mid-loop context expiration break:
	//    With 3 candidates and 3s budget, attempt 0 must get ~1s (not 1.5s/3s);
	//    if attemptCtx cancels during attempt 1, attempt 2 must NEVER be dialed!
	t.Run("FairBudgetAndMidLoopContextBreak", func(t *testing.T) {
		cands := []netip.Addr{
			netip.MustParseAddr("198.51.100.1"),
			netip.MustParseAddr("198.51.100.2"),
			netip.MustParseAddr("2001:db8::1"),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		var timeouts []time.Duration
		var networks []string
		_, err := dialCandidateAddrs(
			ctx,
			cands,
			443,
			acl.OutboundNode{Type: "direct"},
			acl.OutboundTarget{Action: acl.ActionDirect},
			3*time.Second,
			func(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
				timeouts = append(timeouts, d.Timeout)
				networks = append(networks, network)
				if len(networks) == 2 {
					cancel() // expire context before candidate 2 (tcp6)
					return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ETIMEDOUT}
				}
				return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ECONNREFUSED}
			},
		)
		if len(networks) != 2 {
			t.Fatalf("expected loop to break on expired attemptCtx before dialing candidate 2, got %v", networks)
		}
		if timeouts[0] > 1200*time.Millisecond || timeouts[0] < 800*time.Millisecond {
			t.Fatalf("expected attempt 0 timeout ~1s (budget/3), got %v", timeouts[0])
		}
		if !errors.Is(err, syscall.ETIMEDOUT) {
			t.Fatalf("expected last v4 ETIMEDOUT preserved after loop break, got %v", err)
		}
	})

	// 3. ipv6_first fallback: IPv6 fails with ENETUNREACH -> falls back to IPv4 ->
	//    returns IPv4 ECONNREFUSED (not IPv6 ENETUNREACH) when IPv4 fails, and succeeds when IPv4 succeeds.
	t.Run("IPv6FirstFallbackErrorPrecedence", func(t *testing.T) {
		dnsAddr, stopDNS := startMockDualStackDNS(t, [][4]byte{{198, 51, 100, 1}}, [][16]byte{v6IP})
		defer stopDNS()

		res := dns.NewResolver("", "", []string{dnsAddr}, "ipv6_first")
		var mu sync.Mutex
		var tried []string
		_, err := dialDirectWithDNSAndRouteDialer(
			context.Background(),
			"dual-fail.example.test",
			443,
			acl.OutboundNode{Type: "direct"},
			acl.OutboundTarget{Action: acl.ActionDirect},
			res,
			2*time.Second,
			func(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
				mu.Lock()
				tried = append(tried, network+" "+addr)
				mu.Unlock()
				if network == "tcp6" {
					return nil, &net.OpError{Op: "dial", Net: "tcp6", Err: syscall.ENETUNREACH}
				}
				return nil, &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.ECONNREFUSED}
			},
		)
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("expected IPv4 ECONNREFUSED over IPv6 ENETUNREACH, got %v (tried=%v)", err, tried)
		}
		if len(tried) != 2 {
			t.Fatalf("expected 1 tcp6 + 1 tcp4 attempt, got %v", tried)
		}
	})
}
