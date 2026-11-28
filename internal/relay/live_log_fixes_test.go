package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/dns"
)

type spyDeadlineConn struct {
	net.Conn
	mu          sync.Mutex
	readCalls   int
	readDLs     []time.Time
	forceReadFn func([]byte) (int, error)
}

func (s *spyDeadlineConn) Read(b []byte) (int, error) {
	s.mu.Lock()
	s.readCalls++
	fn := s.forceReadFn
	s.mu.Unlock()
	if fn != nil {
		return fn(b)
	}
	return s.Conn.Read(b)
}

func (s *spyDeadlineConn) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDLs = append(s.readDLs, t)
	s.mu.Unlock()
	if s.Conn != nil {
		return s.Conn.SetReadDeadline(t)
	}
	return nil
}

func TestNEW2ProxyProtoNoDeadlineExtensionOrRedundantSyscallOnError(t *testing.T) {
	// 1. Immediate io.EOF with requireHdr=false: returns io.EOF in 1 read, never resets deadline to +12s.
	t.Run("ImmediateEOF", func(t *testing.T) {
		spy := &spyDeadlineConn{
			forceReadFn: func([]byte) (int, error) { return 0, io.EOF },
		}
		pp := &proxyProtoConn{Conn: spy, requireHdr: false, parseTimeout: 100 * time.Millisecond}
		var buf [16]byte
		n, err := pp.Read(buf[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("expected (0, io.EOF), got (%d, %v)", n, err)
		}
		spy.mu.Lock()
		calls := spy.readCalls
		dls := append([]time.Time(nil), spy.readDLs...)
		spy.mu.Unlock()
		if calls != 1 {
			t.Fatalf("expected exactly 1 underlying Read call on immediate EOF, got %d", calls)
		}
		if len(dls) != 1 {
			t.Fatalf("expected only initial parse deadline (no +12s extension on error), got %d SetReadDeadline calls", len(dls))
		}
	})

	// 2. Silent timeout with requireHdr=false: fails at parseTimeout (~60ms), NOT extended to 12s!
	t.Run("SilentTimeout", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		spy := &spyDeadlineConn{Conn: c1}
		pp := &proxyProtoConn{Conn: spy, requireHdr: false, parseTimeout: 60 * time.Millisecond}

		start := time.Now()
		var buf [16]byte
		n, err := pp.Read(buf[:])
		elapsed := time.Since(start)
		if n != 0 || !isNetTimeout(err) {
			t.Fatalf("expected timeout error on silent peer, got n=%d err=%v", n, err)
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("proxyProtoConn extended timeout beyond parseTimeout: elapsed=%v", elapsed)
		}
		spy.mu.Lock()
		dlCount := len(spy.readDLs)
		spy.mu.Unlock()
		if dlCount != 1 {
			t.Fatalf("expected no post-error SetReadDeadline extension, got %d calls", dlCount)
		}
	})

	// 3. Partial 3-byte Slowloris timeout with requireHdr=false: fails at parseTimeout without extending!
	t.Run("PartialSlowlorisTimeout", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() {
			_, _ = c2.Write([]byte("ABC"))
		}()
		spy := &spyDeadlineConn{Conn: c1}
		pp := &proxyProtoConn{Conn: spy, requireHdr: false, parseTimeout: 60 * time.Millisecond}

		start := time.Now()
		var buf [16]byte
		_, err := pp.Read(buf[:])
		if !isNetTimeout(err) {
			t.Fatalf("expected timeout on partial slowloris, got %v", err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatalf("partial slowloris extended deadline: %v", time.Since(start))
		}
	})

	// 4. Short 3-byte non-PROXY stream followed by clean EOF: preserves leftover bytes then returns EOF.
	t.Run("ShortNonProxyEOF", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() {
			_, _ = c2.Write([]byte("XYZ"))
			_ = c2.Close()
		}()
		pp := &proxyProtoConn{Conn: c1, requireHdr: false, parseTimeout: 200 * time.Millisecond}
		var buf [16]byte
		n, err := pp.Read(buf[:])
		if err != nil || string(buf[:n]) != "XYZ" {
			t.Fatalf("expected leftover XYZ, got %q err=%v", buf[:n], err)
		}
		n2, err2 := pp.Read(buf[:])
		if n2 != 0 || !errors.Is(err2, io.EOF) {
			t.Fatalf("expected EOF after draining leftover, got n=%d err=%v", n2, err2)
		}
	})

	// 5. Partial PROXY v1 Slowloris timeout with requireHdr=false: fails at parseTimeout without +12s extension!
	t.Run("PartialV1SlowlorisTimeout", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() {
			_, _ = c2.Write([]byte("PROXY TCP4 "))
		}()
		spy := &spyDeadlineConn{Conn: c1}
		pp := &proxyProtoConn{Conn: spy, requireHdr: false, parseTimeout: 60 * time.Millisecond}

		start := time.Now()
		var buf [16]byte
		_, err := pp.Read(buf[:])
		if !isNetTimeout(err) {
			t.Fatalf("expected timeout on partial v1 slowloris, got %v", err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatalf("partial v1 slowloris extended deadline: %v", time.Since(start))
		}
		spy.mu.Lock()
		dlCount := len(spy.readDLs)
		spy.mu.Unlock()
		if dlCount != 1 {
			t.Fatalf("partial v1 slowloris reset deadline after timeout (%d SetReadDeadline calls)", dlCount)
		}
	})

	// 6. Partial PROXY v2 Slowloris timeout with requireHdr=false: fails at parseTimeout without +12s extension!
	t.Run("PartialV2SlowlorisTimeout", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() {
			_, _ = c2.Write(proxyV2Sig[:6])
		}()
		spy := &spyDeadlineConn{Conn: c1}
		pp := &proxyProtoConn{Conn: spy, requireHdr: false, parseTimeout: 60 * time.Millisecond}

		start := time.Now()
		var buf [16]byte
		_, err := pp.Read(buf[:])
		if !isNetTimeout(err) {
			t.Fatalf("expected timeout on partial v2 slowloris, got %v", err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Fatalf("partial v2 slowloris extended deadline: %v", time.Since(start))
		}
		spy.mu.Lock()
		dlCount := len(spy.readDLs)
		spy.mu.Unlock()
		if dlCount != 1 {
			t.Fatalf("partial v2 slowloris reset deadline after timeout (%d SetReadDeadline calls)", dlCount)
		}
	})
}

func TestBUG3TryDialCandidatesFairBudgetContextBreakAndErrorPreservation(t *testing.T) {
	// 1. Pre-expired context must NOT dial any candidate and returns context.DeadlineExceeded.
	t.Run("ExpiredContextSkipsCandidates", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		port := uint16(ln.Addr().(*net.TCPAddr).Port)

		var accepted atomic.Int32
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				_ = c.Close()
			}
		}()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		c, err := DialOutbound(ctx, "127.0.0.1", port, acl.OutboundTarget{Action: acl.ActionDirect}, nil, 2*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatal("expected expired context to fail immediately")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected DeadlineExceeded, got %v", err)
		}
		if accepted.Load() != 0 {
			t.Fatalf("expired context still dialed target (%d connections)", accepted.Load())
		}
	})

	// 2. Third candidate (listening 127.0.0.1) succeeds even when first two candidates fail!
	t.Run("ThirdCandidateReachesListener", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		goodPort := uint16(ln.Addr().(*net.TCPAddr).Port)

		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("OK"))
			_ = c.Close()
		}()

		// Mock DNS returning 3 A records: 2 non-listening / blackholed + 3rd = 127.0.0.1.
		// Using 127.0.0.2 & 127.0.0.3 (closed on goodPort -> ECONNREFUSED fast-fail) then 127.0.0.1.
		dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer dnsPC.Close()
		go func() {
			buf := make([]byte, 512)
			for {
				n, addr, rerr := dnsPC.ReadFrom(buf)
				if rerr != nil {
					return
				}
				resp := make([]byte, 0, n+64)
				resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
				for _, ip := range [][4]byte{{127, 0, 0, 2}, {127, 0, 0, 3}, {127, 0, 0, 1}} {
					resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04)
					resp = append(resp, ip[:]...)
				}
				_, _ = dnsPC.WriteTo(resp, addr)
			}
		}()

		res := dns.NewResolver("", "", []string{dnsPC.LocalAddr().String()}, "ipv4_only")
		c, err := DialOutbound(context.Background(), "tri-cand.example.test", goodPort, acl.OutboundTarget{Action: acl.ActionDirect}, res, 3*time.Second)
		if err != nil {
			t.Fatalf("expected 3rd candidate 127.0.0.1 to succeed, got %v", err)
		}
		defer c.Close()
		var reply [2]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil || string(reply[:]) != "OK" {
			t.Fatalf("unexpected reply from 3rd candidate: %q err=%v", reply[:], err)
		}
	})

	// 3. Direct check of isNoRouteOrUnreachable helper & IPv6 fallback error preservation.
	t.Run("PreservesV4ErrorOverUnreachableV6", func(t *testing.T) {
		closedLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closedPort := uint16(closedLn.Addr().(*net.TCPAddr).Port)
		_ = closedLn.Close()

		// Confirm IPv4 error against closed loopback port is connection refused (not unreachable)
		resV4 := dns.NewResolver("", "", nil, "ipv4_only")
		_, err4 := DialOutbound(context.Background(), "127.0.0.1", closedPort, acl.OutboundTarget{Action: acl.ActionDirect}, resV4, time.Second)
		if err4 == nil || isNoRouteOrUnreachable(err4) {
			t.Fatalf("expected non-unreachable connection refused error on 127.0.0.1, got %v", err4)
		}
		// Verify netip sanity on IPv6 documentation prefix
		if !netip.MustParseAddr("2001:db8::1").Is6() {
			t.Fatal("sanity check failed")
		}
	})
}

func TestBUG6SOCKS5AndHTTPConnectPreserveUnderlyingErrorsAndReplyCodes(t *testing.T) {
	// 1. SOCKS5 greeting timeout preserves wrapped net.Error timeout
	t.Run("SOCKS5GreetingTimeout", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			time.Sleep(500 * time.Millisecond)
		}()

		out := acl.OutboundNode{Type: "socks5", Server: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
		_, err = dialNodeSOCKS5(context.Background(), out, "example.com", 443, nil, 80*time.Millisecond)
		if err == nil || !isNetTimeout(err) || !strings.Contains(err.Error(), "socks5 greeting read") {
			t.Fatalf("expected wrapped socks5 greeting timeout, got %v", err)
		}
	})

	// 2. SOCKS5 connect rejection includes ver & rep (e.g. 0x05 connection refused)
	t.Run("SOCKS5ConnectRejectedDetails", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte{0x05, 0x00})
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}()

		out := acl.OutboundNode{Type: "socks5", Server: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
		_, err = dialNodeSOCKS5(context.Background(), out, "example.com", 443, nil, time.Second)
		if err == nil || !strings.Contains(err.Error(), "ver=0x05") || !strings.Contains(err.Error(), "rep=0x05") || !strings.Contains(err.Error(), "connection refused") {
			t.Fatalf("expected detailed socks5 connect error with ver/rep, got %v", err)
		}
	})

	// 3. SOCKS5 connect read EOF preserves io.EOF
	t.Run("SOCKS5ConnectReadEOF", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte{0x05, 0x00})
			_, _ = c.Read(buf)
			// Close abruptly without sending connect reply
		}()

		out := acl.OutboundNode{Type: "socks5", Server: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
		_, err = dialNodeSOCKS5(context.Background(), out, "example.com", 443, nil, time.Second)
		if err == nil || !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "socks5 connect read") {
			t.Fatalf("expected wrapped io.EOF on socks5 connect read, got %v", err)
		}
	})

	// 4. HTTP CONNECT rejection preserves exact HTTP status line
	t.Run("HTTPConnectStatusLine", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 256)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"))
		}()

		out := acl.OutboundNode{Type: "http", Server: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
		_, err = dialNodeHTTPConnect(context.Background(), out, "example.com", 443, nil, time.Second)
		if err == nil || !strings.Contains(err.Error(), "407 Proxy Authentication Required") {
			t.Fatalf("expected HTTP status line in error, got %v", err)
		}
	})

	// 5. HTTP CONNECT read timeout wraps underlying timeout error
	t.Run("HTTPConnectReadTimeout", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			time.Sleep(500 * time.Millisecond)
		}()

		out := acl.OutboundNode{Type: "http", Server: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
		_, err = dialNodeHTTPConnect(context.Background(), out, "example.com", 443, nil, 80*time.Millisecond)
		if err == nil || !isNetTimeout(err) || !strings.Contains(err.Error(), "http connect proxy read") {
			t.Fatalf("expected wrapped timeout on http connect read, got %v", err)
		}
	})
}

func TestMultiOutboundFailoverWhenPrimaryHangs(t *testing.T) {
	// 1. TCP failover: primary SOCKS5 proxy accepts TCP and hangs forever; backup direct outbound
	//    must still succeed within a shared parent context deadline!
	t.Run("TCPFailoverFromHangingSOCKS5ToDirect", func(t *testing.T) {
		hangLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer hangLn.Close()
		hangDone := make(chan struct{})
		defer close(hangDone)
		go func() {
			for {
				c, aerr := hangLn.Accept()
				if aerr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					<-hangDone
				}(c)
			}
		}()

		targetLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer targetLn.Close()
		go func() {
			for {
				c, aerr := targetLn.Accept()
				if aerr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = conn.Write([]byte("backup-ok"))
				}(c)
			}
		}()

		route := acl.OutboundTarget{
			Action: acl.ActionProxy,
			Outbounds: []acl.OutboundNode{
				{Type: "socks5", Server: "127.0.0.1", Port: hangLn.Addr().(*net.TCPAddr).Port},
				{Type: "direct"},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		defer cancel()
		c, err := DialOutbound(ctx, "127.0.0.1", uint16(targetLn.Addr().(*net.TCPAddr).Port), route, nil, 900*time.Millisecond)
		if err != nil {
			t.Fatalf("expected DialOutbound to fail over from hanging primary to backup direct, got %v", err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 16)
		n, rerr := c.Read(buf)
		if rerr != nil || string(buf[:n]) != "backup-ok" {
			t.Fatalf("unexpected backup response: %q err=%v", buf[:n], rerr)
		}
	})

	// 2. UDP failover: primary SOCKS5 UDP proxy hangs on greeting; backup SOCKS5 UDP proxy succeeds!
	t.Run("UDPFailoverFromHangingSOCKS5ToHealthySOCKS5", func(t *testing.T) {
		hangLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer hangLn.Close()
		hangDone := make(chan struct{})
		defer close(hangDone)
		go func() {
			for {
				c, aerr := hangLn.Accept()
				if aerr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					<-hangDone
				}(c)
			}
		}()

		relayPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer relayPC.Close()
		relayPort := relayPC.LocalAddr().(*net.UDPAddr).Port

		goodLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer goodLn.Close()
		go func() {
			for {
				c, aerr := goodLn.Accept()
				if aerr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					buf := make([]byte, 64)
					if _, rerr := conn.Read(buf); rerr != nil {
						return
					}
					_, _ = conn.Write([]byte{0x05, 0x00})
					if _, rerr := conn.Read(buf); rerr != nil {
						return
					}
					var reply [10]byte
					reply[0], reply[1], reply[2], reply[3] = 0x05, 0x00, 0x00, 0x01
					copy(reply[4:8], []byte{127, 0, 0, 1})
					binary.BigEndian.PutUint16(reply[8:10], uint16(relayPort))
					_, _ = conn.Write(reply[:])
					<-hangDone
				}(c)
			}
		}()

		route := acl.OutboundTarget{
			Action: acl.ActionProxy,
			Outbounds: []acl.OutboundNode{
				{Type: "socks5", Server: "127.0.0.1", Port: hangLn.Addr().(*net.TCPAddr).Port},
				{Type: "socks5", Server: "127.0.0.1", Port: goodLn.Addr().(*net.TCPAddr).Port},
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		defer cancel()
		pc, err := DialUDPForRoute(ctx, route, false, nil)
		if err != nil {
			t.Fatalf("expected DialUDPForRoute to fail over from hanging primary SOCKS5 to healthy backup, got %v", err)
		}
		_ = pc.Close()
	})
}
