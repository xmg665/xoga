package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/limiter"
)

func TestH3PipeBidirectionalSurvivesUnidirectionalTransferExceedingIdle(t *testing.T) {
	for _, zeroCopy := range []bool{false, true} {
		name := "userspace"
		if zeroCopy {
			name = "zerocopy"
		}
		t.Run(name, func(t *testing.T) {
			// Sink server: reads continuously for ~450ms (> 2.5x 150ms idleTimeout), sending NOTHING back until client closes write.
			sinkLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer sinkLn.Close()

			var serverGot int
			var srvMu sync.Mutex
			go func() {
				c, err := sinkLn.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				b, _ := io.ReadAll(c)
				srvMu.Lock()
				serverGot = len(b)
				srvMu.Unlock()
				_, _ = c.Write([]byte("DONE"))
			}()

			proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer proxyLn.Close()

			go func() {
				cli, err := proxyLn.Accept()
				if err != nil {
					return
				}
				defer cli.Close()
				rem, err := net.Dial("tcp", sinkLn.Addr().String())
				if err != nil {
					return
				}
				defer rem.Close()
				var c net.Conn = cli
				if !zeroCopy {
					c = &nonTCPWrapper{Conn: cli}
				}
				PipeBidirectional(c, rem, nil, nil, limiter.NewBucketMbps(0), 150*time.Millisecond, zeroCopy)
			}()

			cli, err := net.Dial("tcp", proxyLn.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()

			// Continuously upload 1 KiB every 40ms for 440ms (~3x idleTimeout) with ZERO download bytes
			chunk := bytes.Repeat([]byte("U"), 1024)
			for i := 0; i < 11; i++ {
				if _, err := cli.Write(chunk); err != nil {
					t.Fatalf("unidirectional upload killed at step %d: %v", i, err)
				}
				time.Sleep(40 * time.Millisecond)
			}
			_ = cli.(*net.TCPConn).CloseWrite()

			var done [4]byte
			_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.ReadFull(cli, done[:]); err != nil || string(done[:]) != "DONE" {
				t.Fatalf("expected DONE after unidirectional upload, got %q err=%v", done[:], err)
			}
			srvMu.Lock()
			got := serverGot
			srvMu.Unlock()
			if got != 11*1024 {
				t.Fatalf("expected %d uploaded bytes, server got %d", 11*1024, got)
			}
		})
	}
}

func TestN5TimeoutResumableVLESSAndSSAndWSClientConns(t *testing.T) {
	// 1. vlessClientConn: read timeout BEFORE & MID 2-byte response header + addon must resume cleanly
	t.Run("vlessClientConn", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		vc := &vlessClientConn{Conn: c1}
		go func() {
			time.Sleep(50 * time.Millisecond)
			_, _ = c2.Write([]byte{0x00}) // byte 1 of VLESS resp header
			time.Sleep(50 * time.Millisecond)
			_, _ = c2.Write([]byte{0x02, 0xaa}) // addonLen=2 + byte 1 of addon
			time.Sleep(50 * time.Millisecond)
			_, _ = c2.Write([]byte{0xbb}) // byte 2 of addon
			_, _ = c2.Write([]byte("vless-ok"))
		}()

		var dst [32]byte
		for attempt := 0; attempt < 10; attempt++ {
			_ = vc.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			n, err := vc.Read(dst[:])
			if err == nil {
				if string(dst[:n]) != "vless-ok" {
					t.Fatalf("vlessClientConn corrupted payload after header timeouts: got %q", dst[:n])
				}
				return
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("unexpected vlessClientConn error: %v", err)
			}
		}
		t.Fatal("vlessClientConn did not complete within retries")
	})

	// 2. ssClientConn: Write timeout before wire write keeps pendingHdr/nonce intact; Read resumes mid-salt/len/chunk
	t.Run("ssClientConn", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		mk := deriveEVPKey("test-ss-pass", 16)
		hdr := appendSOCKS5Target(nil, "127.0.0.1", 80)
		ss := &ssClientConn{
			Conn:       c1,
			keyLen:     16,
			masterKey:  mk,
			pendingHdr: hdr,
		}

		// Force immediate write timeout (nw == 0) -> pendingHdr & writeAEAD MUST remain intact!
		_ = ss.SetWriteDeadline(time.Now().Add(-time.Second))
		if _, err := ss.Write([]byte("payload")); err == nil {
			t.Fatal("expected write timeout on expired deadline")
		}
		if len(ss.pendingHdr) == 0 || ss.writeAEAD != nil {
			t.Fatal("ssClientConn mutated pendingHdr/writeAEAD despite 0 bytes written on timeout")
		}
		_ = ss.SetWriteDeadline(time.Time{})

		// Drain client write in background and send server response split across timeouts
		go func() {
			buf := make([]byte, 512)
			_, _ = c2.Read(buf)

			var srvSalt [16]byte
			_, _ = rand.Read(srvSalt[:])
			aead, _ := ss.makeSubAEAD(srvSalt[:])
			var nonce [12]byte
			msg := []byte("ss-resumed-ok")
			var lb [2]byte
			binary.BigEndian.PutUint16(lb[:], uint16(len(msg)))
			encLen := aead.Seal(nil, nonce[:], lb[:], nil)
			incSSNonce(&nonce)
			encBody := aead.Seal(nil, nonce[:], msg, nil)

			wire := append(append(srvSalt[:], encLen...), encBody...)
			// Drip wire across 4 chunks with delays so Read hits timeouts mid-salt, mid-len, and mid-chunk!
			splits := []int{5, 22, 40, len(wire)}
			prev := 0
			for _, end := range splits {
				_, _ = c2.Write(wire[prev:end])
				prev = end
				time.Sleep(45 * time.Millisecond)
			}
		}()

		if _, err := ss.Write([]byte("payload")); err != nil {
			t.Fatalf("ssClientConn Write after rollback failed: %v", err)
		}

		var dst [64]byte
		for attempt := 0; attempt < 20; attempt++ {
			_ = ss.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			n, err := ss.Read(dst[:])
			if err == nil {
				if string(dst[:n]) != "ss-resumed-ok" {
					t.Fatalf("ssClientConn corrupted payload after timeouts: got %q", dst[:n])
				}
				return
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("unexpected ssClientConn Read error: %v", err)
			}
		}
		t.Fatal("ssClientConn Read did not finish within retries")
	})

	// 3. wsClientConn: Read timeout mid-frame-header resumes cleanly without desync
	t.Run("wsClientConn", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		wsc := &wsClientConn{Conn: c1, br: bufio.NewReader(c1)}
		payload := []byte("ws-client-resumed-ok")
		frame := append([]byte{0x82, byte(len(payload))}, payload...)
		go func() {
			_, _ = c2.Write(frame[:1])
			time.Sleep(50 * time.Millisecond)
			_, _ = c2.Write(frame[1:])
		}()

		var dst [64]byte
		_ = wsc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, err := wsc.Read(dst[:]); err == nil {
			t.Fatal("expected timeout mid-header")
		}
		_ = wsc.SetReadDeadline(time.Now().Add(time.Second))
		n, err := wsc.Read(dst[:])
		if err != nil || string(dst[:n]) != string(payload) {
			t.Fatalf("wsClientConn resumed Read mismatch: got %q err=%v", dst[:n], err)
		}
	})
}

func TestH4H5M8N10RelaySecurityAndRoutingFixes(t *testing.T) {
	// H4: socks5UDPPacketConn.WriteTo rejects nil addr / nil IP cleanly
	spc := &socks5UDPPacketConn{}
	if _, err := spc.WriteTo([]byte("hi"), (*net.UDPAddr)(nil)); err == nil {
		t.Fatal("expected error for nil *net.UDPAddr")
	}
	if _, err := spc.WriteTo([]byte("hi"), &net.UDPAddr{Port: 53}); err == nil {
		t.Fatal("expected error for nil IP in *net.UDPAddr")
	}

	// H5: DialUDPForRoute MUST NOT fall back to direct when proxy route fails or is non-SOCKS5
	httpRoute := acl.OutboundTarget{
		Action: acl.ActionProxy,
		Outbounds: []acl.OutboundNode{
			{Type: "http", Server: "127.0.0.1", Port: 1},
		},
	}
	if pc, err := DialUDPForRoute(context.Background(), httpRoute, false, nil); err == nil {
		_ = pc.Close()
		t.Fatal("DialUDPForRoute leaked direct socket on non-SOCKS5 proxy route")
	}
	deadSOCKS := acl.OutboundTarget{
		Action: acl.ActionProxy,
		Outbounds: []acl.OutboundNode{
			{Type: "socks5", Server: "127.0.0.1", Port: 1},
		},
	}
	if pc, err := DialUDPForRoute(context.Background(), deadSOCKS, false, nil); err == nil {
		_ = pc.Close()
		t.Fatal("DialUDPForRoute leaked direct socket on failed SOCKS5 proxy route")
	}

	// H5: IPv4-only direct listen route MUST refuse unbound IPv6 TCP and UDP dials
	v4OnlyRoute := acl.OutboundTarget{
		Action: acl.ActionProxy,
		Outbounds: []acl.OutboundNode{
			{Type: "direct", ListenIPv4: "127.0.0.1"},
		},
	}
	if c, err := DialOutbound(context.Background(), "::1", 80, v4OnlyRoute, nil, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("IPv4-only direct route allowed unbound IPv6 TCP dial")
	}
	if _, err := ResolveUDPTargetForRoute(context.Background(), "::1", 53, v4OnlyRoute, nil); err == nil {
		t.Fatal("IPv4-only direct route allowed IPv6 UDP target resolution")
	}
	if pc, err := DialUDPForRoute(context.Background(), v4OnlyRoute, true, nil); err == nil {
		_ = pc.Close()
		t.Fatal("IPv4-only direct route allowed unbound IPv6 UDP socket")
	}

	// M8: dialNodeShadowsocks rejects unsupported ciphers instead of silently using aes-256-gcm
	if _, err := dialNodeShadowsocks(context.Background(), acl.OutboundNode{
		Type: "ss", Server: "127.0.0.1", Port: 1, Cipher: "aes-128-cfb", Password: "p",
	}, "1.1.1.1", 80, nil, time.Second); err == nil {
		t.Fatal("expected unsupported SS outbound cipher to return error")
	}

	// M8: clientWSHandshake brackets IPv6 in Host header and rejects mismatched Sec-WebSocket-Accept
	t.Run("clientWSHandshake_IPv6_And_AcceptCheck", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		var gotHost string
		done := make(chan struct{})
		go func() {
			defer close(done)
			br := bufio.NewReader(c2)
			for {
				line, err := br.ReadString('\n')
				if err != nil || strings.TrimSpace(line) == "" {
					break
				}
				if strings.HasPrefix(strings.ToLower(line), "host:") {
					gotHost = strings.TrimSpace(line[5:])
				}
			}
			// Reply with WRONG Sec-WebSocket-Accept
			_, _ = c2.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong-accept\r\n\r\n"))
		}()

		if _, err := clientWSHandshake(c1, acl.OutboundNode{Server: "2001:db8::1", WSPath: "/ws"}); err == nil {
			t.Fatal("expected clientWSHandshake to reject mismatched Sec-WebSocket-Accept")
		}
		<-done
		if gotHost != "[2001:db8::1]" {
			t.Fatalf("expected bracketed IPv6 Host header [2001:db8::1], got %q", gotHost)
		}

		// Verify valid Sec-WebSocket-Accept succeeds
		c3, c4 := net.Pipe()
		defer c3.Close()
		defer c4.Close()
		go func() {
			br := bufio.NewReader(c4)
			var wsKey string
			for {
				line, err := br.ReadString('\n')
				if err != nil || strings.TrimSpace(line) == "" {
					break
				}
				if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "sec-websocket-key") {
					wsKey = strings.TrimSpace(v)
				}
			}
			h := sha1.New()
			_, _ = h.Write([]byte(wsKey))
			_, _ = h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			acc := base64.StdEncoding.EncodeToString(h.Sum(nil))
			_, _ = c4.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acc + "\r\n\r\n"))
		}()
		if _, err := clientWSHandshake(c3, acl.OutboundNode{Server: "2001:db8::1", WSPath: "/ws"}); err != nil {
			t.Fatalf("valid clientWSHandshake failed: %v", err)
		}
	})

	// N10: Non-PROXY 8-byte initial payload must NOT stall 5 seconds in proxyProtoConn
	t.Run("proxyProtoNoStallOnShortNonProxy", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		pp := &proxyProtoConn{Conn: c1, requireHdr: false}

		go func() {
			_, _ = c2.Write([]byte("HELLO123")) // 8 bytes, neither "PROXY " nor v2 sig; keep socket open!
		}()

		start := time.Now()
		buf := make([]byte, 16)
		n, err := pp.Read(buf)
		elapsed := time.Since(start)
		if err != nil || string(buf[:n]) != "HELLO123" {
			t.Fatalf("expected immediate HELLO123 read, got %q err=%v", buf[:n], err)
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("non-PROXY 8-byte payload stalled %v (expected <50ms)", elapsed)
		}
	})
}

func startMockDualStackUDPDNS(t *testing.T, v4 [4]byte, v6 [16]byte) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			qtype := binary.BigEndian.Uint16(buf[n-4 : n-2])
			resp := make([]byte, 0, n+32)
			resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
			resp = append(resp, buf[12:n]...)
			resp = append(resp, 0xC0, 0x0C)
			var tail [10]byte
			binary.BigEndian.PutUint16(tail[0:2], qtype)
			binary.BigEndian.PutUint16(tail[2:4], 1)
			binary.BigEndian.PutUint32(tail[4:8], 60)
			if qtype == 1 {
				binary.BigEndian.PutUint16(tail[8:10], 4)
				resp = append(resp, tail[:]...)
				resp = append(resp, v4[:]...)
			} else if qtype == 28 {
				binary.BigEndian.PutUint16(tail[8:10], 16)
				resp = append(resp, tail[:]...)
				resp = append(resp, v6[:]...)
			} else {
				continue
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func TestM2BlackholedIPv6FallbackToIPv4WithinBudget(t *testing.T) {
	// Real IPv4 TCP echo listener on 127.0.0.1; AAAA points to RFC 6666 discard/blackhole IPv6 (100::1)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("V4_FALLBACK_OK"))
			}(c)
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// RFC 6666 discard prefix 100::1 (blackholed or unreachable IPv6) + 127.0.0.1 IPv4
	v6Discard := [16]byte{0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dnsAddr, stopDNS := startMockDualStackUDPDNS(t, [4]byte{127, 0, 0, 1}, v6Discard)
	defer stopDNS()

	res := dns.NewResolver("", "", []string{dnsAddr}, "ipv6_first")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c, err := DialOutbound(ctx, "dualstack-fb.example.com", port, acl.OutboundTarget{Action: acl.ActionDirect}, res, 1200*time.Millisecond)
	if err != nil {
		t.Fatalf("M2 ipv6_first -> ipv4_only fallback failed: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "V4_FALLBACK_OK" {
		t.Fatalf("unexpected IPv4 fallback payload: got %q err=%v", got, err)
	}
}

type scriptReadConn struct {
	net.Conn
	readBuf    []byte
	eofOnLast  bool
	writeLimit int
	writeCalls int
}

func (c *scriptReadConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 && c.eofOnLast {
		return n, io.EOF
	}
	return n, nil
}

func (c *scriptReadConn) Write(p []byte) (int, error) {
	c.writeCalls++
	if c.writeLimit > 0 && len(p) > c.writeLimit {
		return c.writeLimit, errors.New("simulated partial write error")
	}
	return len(p), nil
}

type nilAddrPacketConn struct {
	net.PacketConn
}

func (n *nilAddrPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 4, nil, nil
}

func TestOutboundWrappersEOFCompletionSSWriteBrokenAndDialUDPFailover(t *testing.T) {
	// 1. ssClientConn.Read must NOT drop final chunk when underlying Conn.Read returns (remaining, io.EOF)
	t.Run("ssClientConn_EOFOnFinalChunk", func(t *testing.T) {
		mk := deriveEVPKey("eof-test-pass", 16)
		ss := &ssClientConn{
			keyLen:    16,
			masterKey: mk,
		}
		var srvSalt [16]byte
		_, _ = rand.Read(srvSalt[:])
		aead, err := ss.makeSubAEAD(srvSalt[:])
		if err != nil {
			t.Fatal(err)
		}
		var nonce [12]byte
		msg := []byte("ss-final-chunk-preserved")
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(msg)))
		encLen := aead.Seal(nil, nonce[:], lb[:], nil)
		incSSNonce(&nonce)
		encBody := aead.Seal(nil, nonce[:], msg, nil)
		wire := append(append(srvSalt[:], encLen...), encBody...)

		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		ss.Conn = &scriptReadConn{Conn: c1, readBuf: wire, eofOnLast: true}

		dst := make([]byte, 64)
		n, err := ss.Read(dst)
		if err != nil || string(dst[:n]) != string(msg) {
			t.Fatalf("ssClientConn dropped final chunk on (n, io.EOF): got %q err=%v", dst[:n], err)
		}
	})

	// 2. ssClientConn.flushTargetHeaderIfNeeded MUST reject after Write hit partial write (writeBroken=true)
	t.Run("ssClientConn_WriteBrokenGuardsFlush", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		sc := &scriptReadConn{Conn: c1, writeLimit: 5}
		ss := &ssClientConn{
			Conn:       sc,
			keyLen:     16,
			masterKey:  deriveEVPKey("broken-pass", 16),
			pendingHdr: appendSOCKS5Target(nil, "127.0.0.1", 80),
		}
		if _, err := ss.Write([]byte("user-payload")); err == nil {
			t.Fatal("expected partial write error")
		}
		callsAfterWrite := sc.writeCalls
		if err := ss.flushTargetHeaderIfNeeded(); err == nil {
			t.Fatal("expected flushTargetHeaderIfNeeded to reject when writeBroken=true")
		}
		if sc.writeCalls != callsAfterWrite {
			t.Fatalf("flushTargetHeaderIfNeeded wrote to wire despite writeBroken=true (calls %d -> %d)", callsAfterWrite, sc.writeCalls)
		}
	})

	// 3. vlessClientConn.Read completes header+addon on (n, io.EOF)
	t.Run("vlessClientConn_EOFOnHeader", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		vc := &vlessClientConn{Conn: &scriptReadConn{Conn: c1, readBuf: []byte{0x00, 0x02, 0xaa, 0xbb}, eofOnLast: true}}
		var dst [8]byte
		n, err := vc.Read(dst[:])
		if n != 0 || err != io.EOF || !vc.readHdr {
			t.Fatalf("expected clean EOF after completing header+addon, got n=%d err=%v readHdr=%v", n, err, vc.readHdr)
		}
	})

	// 4. DialUDPForRoute rejects invalid listen_ipv4/listen_ipv6 AND fails over across multiple direct outbounds
	t.Run("DialUDPForRoute_InvalidListenAndFailover", func(t *testing.T) {
		badRoute := acl.OutboundTarget{
			Action: acl.ActionProxy,
			Outbounds: []acl.OutboundNode{
				{Type: "direct", ListenIPv4: "not-an-ip"},
			},
		}
		if pc, err := DialUDPForRoute(context.Background(), badRoute, false, nil); err == nil {
			_ = pc.Close()
			t.Fatal("DialUDPForRoute leaked unbound socket on invalid listen_ipv4")
		}
		failoverRoute := acl.OutboundTarget{
			Action: acl.ActionProxy,
			Outbounds: []acl.OutboundNode{
				{Type: "direct", ListenIPv4: "203.0.113.254"}, // non-local IP -> bind fails
				{Type: "direct", ListenIPv4: "127.0.0.1"},     // local loopback -> succeeds!
			},
		}
		pc, err := DialUDPForRoute(context.Background(), failoverRoute, false, nil)
		if err != nil {
			t.Fatalf("DialUDPForRoute failed to fail over to 2nd outbound: %v", err)
		}
		defer pc.Close()
		if !strings.HasPrefix(pc.LocalAddr().String(), "127.0.0.1:") {
			t.Fatalf("expected failover socket bound to 127.0.0.1, got %s", pc.LocalAddr())
		}
	})

	// 5. ReadPacketZeroIdle rejects nil addr even on non-*net.UDPConn PacketConn
	t.Run("ReadPacketZeroIdle_NonUDPConnNilAddr", func(t *testing.T) {
		if _, addr, _, bp, err := ReadPacketZeroIdle(&nilAddrPacketConn{}); err == nil || addr != nil || bp != nil {
			t.Fatalf("expected error on nil addr from non-*net.UDPConn, got addr=%v err=%v", addr, err)
		}
	})
}

func TestH3PipeBidirectionalUnidirectionalDownloadRawTCP(t *testing.T) {
	// Source server streams unidirectional downloads continuously for ~450ms (> 2.5x 150ms idleTimeout)
	// while client sends ZERO upload bytes. Exercises tryCopyFromRawTCP on remoteConn + shared lastActive!
	srcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srcLn.Close()

	go func() {
		c, err := srcLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		chunk := bytes.Repeat([]byte("D"), 1024)
		for i := 0; i < 11; i++ {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	go func() {
		cli, err := proxyLn.Accept()
		if err != nil {
			return
		}
		defer cli.Close()
		rem, err := net.Dial("tcp", srcLn.Addr().String())
		if err != nil {
			return
		}
		defer rem.Close()
		// Wrap clientConn so splice is disabled and remoteConn (*net.TCPConn) hits tryCopyFromRawTCP!
		PipeBidirectional(&nonTCPWrapper{Conn: cli}, rem, nil, nil, limiter.NewBucketMbps(0), 150*time.Millisecond, false)
	}()

	cli, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(cli)
	if err != nil {
		t.Fatalf("unidirectional download via tryCopyFromRawTCP failed: %v", err)
	}
	if len(got) != 11*1024 {
		t.Fatalf("expected %d downloaded bytes, got %d", 11*1024, len(got))
	}
}
