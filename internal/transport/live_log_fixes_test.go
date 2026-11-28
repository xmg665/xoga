package transport

import (
	"net"
	"testing"
)

type fakePeerConn struct {
	net.Conn
	peer net.Addr
}

func (f *fakePeerConn) RemoteAddr() net.Addr { return f.peer }

func TestNEW1TrustedProxyCIDRsWebSocketForwardedIP(t *testing.T) {
	prefixes, invalid := ParseTrustedProxyCIDRs([]string{
		"203.175.12.253",
		"172.64.0.0/13",
		"2606:4700::/32",
		"::ffff:43.217.251.51/128",
		"not-a-cidr",
	})
	if len(prefixes) != 4 {
		t.Fatalf("expected 4 valid prefixes, got %d (%v)", len(prefixes), prefixes)
	}
	if len(invalid) != 1 || invalid[0] != "not-a-cidr" {
		t.Fatalf("expected 1 invalid entry, got %v", invalid)
	}

	runWS := func(peerIP string, extraHeaders string, trustAll bool) string {
		t.Helper()
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			req := "GET /ws HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				extraHeaders + "\r\n"
			_, _ = c2.Write([]byte(req))
			buf := make([]byte, 512)
			_, _ = c2.Read(buf)
		}()

		fc := &fakePeerConn{
			Conn: c1,
			peer: &net.TCPAddr{IP: net.ParseIP(peerIP), Port: 54321},
		}
		ws, err := AcceptWebSocketWithTrustedProxies(fc, "/ws", trustAll, prefixes)
		if err != nil {
			t.Fatalf("AcceptWebSocketWithTrustedProxies(peer=%s) failed: %v", peerIP, err)
		}
		defer ws.Close()
		return ws.RemoteAddr().(*net.TCPAddr).IP.String()
	}

	// 1. Public relay IP matching single-IP entry trusts X-Forwarded-For (first hop)
	if got := runWS("203.175.12.253", "X-Forwarded-For: 198.51.100.42, 203.175.12.253\r\n", false); got != "198.51.100.42" {
		t.Fatalf("trusted public relay XFF ignored: got %s want 198.51.100.42", got)
	}

	// 2. Cloudflare CDN CIDR trusts CF-Connecting-IP over X-Real-IP and X-Forwarded-For regardless of header order
	hdrs := "X-Forwarded-For: 198.51.100.1\r\nX-Real-IP: 198.51.100.2\r\nCF-Connecting-IP: 198.51.100.3\r\n"
	if got := runWS("172.64.15.9", hdrs, false); got != "198.51.100.3" {
		t.Fatalf("trusted CDN CIDR priority failed: got %s want 198.51.100.3", got)
	}

	// 3. IPv4-mapped IPv6 prefix matches IPv4 peer; X-Real-IP takes priority over X-Forwarded-For
	if got := runWS("43.217.251.51", "X-Forwarded-For: 198.51.100.10\r\nX-Real-IP: 198.51.100.20:4444\r\n", false); got != "198.51.100.20" {
		t.Fatalf("trusted v4-in-v6 peer failed: got %s want 198.51.100.20", got)
	}

	// 4. IPv6 trusted CDN CIDR trusts forwarded IPv6 client address
	if got := runWS("2606:4700::1234", "CF-Connecting-IP: 2001:db8::99\r\n", false); got != "2001:db8::99" {
		t.Fatalf("trusted IPv6 CDN CIDR failed: got %s want 2001:db8::99", got)
	}

	// 5. Untrusted public IP MUST ignore spoofed forwarded headers when trustAll=false
	if got := runWS("192.0.2.88", "CF-Connecting-IP: 198.51.100.99\r\nX-Forwarded-For: 198.51.100.98\r\n", false); got != "192.0.2.88" {
		t.Fatalf("untrusted public peer spoofed forwarded IP: got %s want 192.0.2.88", got)
	}

	// 6. trustAll=true trusts forwarded headers from any public peer
	if got := runWS("192.0.2.88", "X-Forwarded-For: 198.51.100.77\r\n", true); got != "198.51.100.77" {
		t.Fatalf("trustAll=true ignored forwarded IP: got %s want 198.51.100.77", got)
	}

	// 7. Loopback/private peer continues to trust forwarded headers by default
	if got := runWS("127.0.0.1", "X-Real-IP: 198.51.100.55\r\n", false); got != "198.51.100.55" {
		t.Fatalf("loopback peer ignored forwarded IP: got %s want 198.51.100.55", got)
	}
}
