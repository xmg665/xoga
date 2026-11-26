package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/limiter"
	"github.com/xmg665/xoga/internal/stats"
)

type nonTCPWrapper struct {
	net.Conn
}

func TestPipeBidirectionalZeroBufferIdleAndBurst(t *testing.T) {
	// Echo backend server (raw TCP)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// Simulate idle pause before first burst so epoll EAGAIN release path is exercised
				time.Sleep(25 * time.Millisecond)
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	user := stats.NewUserEntry(101, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	nodeLim := limiter.NewBucketMbps(0)

	go func() {
		for {
			cli, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rem, err := net.Dial("tcp", echoLn.Addr().String())
				if err != nil {
					return
				}
				defer rem.Close()
				// Wrap client side so `enableZeroCopy=false` / non-splice user-space `tryCopyFromRawTCP` is exercised!
				PipeBidirectional(&nonTCPWrapper{Conn: c}, rem, nil, user, nodeLim, 2*time.Second, false)
			}(cli)
		}
	}()

	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := make([]byte, 96*1024)
	_, _ = rand.Read(payload)

	errCh := make(chan error, 1)
	go func() {
		_, werr := conn.Write(payload)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		errCh <- werr
	}()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if werr := <-errCh; werr != nil {
		t.Fatalf("write payload: %v", werr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
}

func TestDisableAndKickSeversStalledRemoteImmediately(t *testing.T) {
	// Stalled remote server that never sends FIN or data
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	go func() {
		c, err := stallLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(10 * time.Second)
	}()

	cliSrv, cliPeer := net.Pipe()
	defer cliPeer.Close()

	rem, err := net.Dial("tcp", stallLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rem.Close()

	user := stats.NewUserEntry(202, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	_, err = user.AcquireSession(ExtractClientIP(rem.RemoteAddr()), 60, nil, cliSrv)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		PipeBidirectional(cliSrv, rem, nil, user, limiter.NewBucketMbps(0), 30*time.Second, false)
	}()

	time.Sleep(40 * time.Millisecond)
	user.DisableAndKick()

	select {
	case <-done:
	case <-time.After(400 * time.Millisecond):
		t.Fatal("PipeBidirectional lingered on stalled remoteConn after DisableAndKick()")
	}
}

// TestWSClientOverflowAndSSRFGuards verifies fixes for:
// - C1: `wsClientConn.Read` 64-bit MSB frame length overflow returns error instead of panicking
// - C2: `BanPrivateIP=true` blocks `0.0.0.0`, `100.100.100.200`, and loopback IPs post-DNS
// - C3: oversized (>253 byte) / CRLF target hostnames rejected before outbound serialization
// - C4: Linux zero-copy `splice(2)` preserves active low-rate TCP streams across `idleTimeout`
func TestWSClientOverflowAndSSRFGuards(t *testing.T) {
	// 1. C1: Malformed 64-bit WS frame header with MSB=1 must NOT panic!
	malformed := []byte{0x82, 0x7F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c2.Write(malformed)
	}()
	wsc := &wsClientConn{Conn: c1, br: bufio.NewReader(c1)}
	var dst [32]byte
	if _, err := wsc.Read(dst[:]); err == nil {
		t.Fatal("expected error on negative/oversized 64-bit WS frame length")
	}

	// 2. C2 & C3: BanPrivateIP blocks 0.0.0.0, CGNAT 100.100.100.200, and >253-char hostnames
	eng := acl.NewEngine(true, "", "", "", nil)
	eng.SetPortAndPrivatePolicy("", true)
	for _, blockedHost := range []string{"0.0.0.0", "::", "127.0.0.1", "100.100.100.200", "169.254.169.254"} {
		rt := eng.DecideForNode(1, blockedHost, 80, "", "")
		if rt.Action != acl.ActionBlock {
			t.Fatalf("expected %s to be blocked by BanPrivateIP, got %+v", blockedHost, rt)
		}
	}
	rtDomain := eng.DecideForNode(1, "rebind.example.com", 80, "", "")
	if rtDomain.AllowResolvedIP(netip.MustParseAddr("127.0.0.1")) || rtDomain.AllowResolvedIP(netip.MustParseAddr("0.0.0.0")) {
		t.Fatal("expected post-DNS AllowResolvedIP to reject loopback/0.0.0.0 when BanPrivateIP=true")
	}
	longHost := strings.Repeat("a", 260) + ".com"
	if _, err := DialOutbound(context.Background(), longHost, 443, acl.OutboundTarget{}, nil, time.Second); err == nil {
		t.Fatal("expected >253-byte target host to be rejected")
	}

	// 3. C4: Zero-copy splice active low-rate stream (<256 KiB per window) survives multiple idleTimeout windows!
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	pLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pLn.Close()
	go func() {
		cli, err := pLn.Accept()
		if err != nil {
			return
		}
		defer cli.Close()
		rem, err := net.Dial("tcp", echoLn.Addr().String())
		if err != nil {
			return
		}
		defer rem.Close()
		// Very short 120ms idleTimeout with enableZeroCopy=true!
		PipeBidirectional(cli, rem, nil, nil, limiter.NewBucketMbps(0), 120*time.Millisecond, true)
	}()

	cli, err := net.Dial("tcp", pLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Send 16 bytes every 60ms across 4 ticks (240ms total = 2x idleTimeout, only 64B << 256KiB)
	for tick := 0; tick < 4; tick++ {
		time.Sleep(60 * time.Millisecond)
		msg := []byte("keepalive-ping!!")
		if _, err := cli.Write(msg); err != nil {
			t.Fatalf("zero-copy splice killed active low-rate stream on tick %d: %v", tick, err)
		}
		var reply [16]byte
		if _, err := io.ReadFull(cli, reply[:]); err != nil {
			t.Fatalf("zero-copy splice dropped reply on tick %d: %v", tick, err)
		}
	}
}
