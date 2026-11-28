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

	runWSWithMode := func(peerIP string, extraHeaders string, trustAll bool, mode ForwardedIPHeaderMode) string {
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
		var ws net.Conn
		var err error
		if mode == "" {
			ws, err = AcceptWebSocketWithTrustedProxies(fc, "/ws", trustAll, prefixes)
		} else {
			ws, err = AcceptWebSocketWithTrustedProxies(fc, "/ws", trustAll, prefixes, mode)
		}
		if err != nil {
			t.Fatalf("AcceptWebSocketWithTrustedProxies(peer=%s, mode=%s) failed: %v", peerIP, mode, err)
		}
		defer ws.Close()
		return ws.RemoteAddr().(*net.TCPAddr).IP.String()
	}
	runWS := func(peerIP string, extraHeaders string, trustAll bool) string {
		t.Helper()
		return runWSWithMode(peerIP, extraHeaders, trustAll, "")
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

	// 3. IPv4-mapped IPv6 prefix matches IPv4 peer:
	//    - X-Real-IP-only (e.g. Nginx without XFF) parses host:port cleanly -> 198.51.100.20
	if got := runWS("43.217.251.51", "X-Real-IP: 198.51.100.20:4444\r\n", false); got != "198.51.100.20" {
		t.Fatalf("trusted v4-in-v6 peer X-Real-IP-only failed: got %s want 198.51.100.20", got)
	}
	//    - Non-Cloudflare L7 relay (e.g. HAProxy `option forwardfor`) with XFF + client-spoofed X-Real-IP
	//      and CF-Connecting-IP MUST prefer right-to-left XFF (198.51.100.10) in default auto mode!
	if got := runWS("43.217.251.51", "CF-Connecting-IP: 198.51.100.30\r\nX-Forwarded-For: 198.51.100.10\r\nX-Real-IP: 198.51.100.20:4444\r\n", false); got != "198.51.100.10" {
		t.Fatalf("non-CF relay allowed CF-Connecting-IP/X-Real-IP spoofing over XFF: got %s want 198.51.100.10", got)
	}
	//    - Explicit ForwardedIPHeaderXRealIP mode (Nginx X-Real-IP-only deployment) strictly honors X-Real-IP
	//      even if client injects spoofed X-Forwarded-For / CF-Connecting-IP!
	if got := runWSWithMode("43.217.251.51", "CF-Connecting-IP: 198.51.100.30\r\nX-Forwarded-For: 198.51.100.10\r\nX-Real-IP: 198.51.100.20:4444\r\n", false, ForwardedIPHeaderXRealIP); got != "198.51.100.20" {
		t.Fatalf("explicit x-real-ip mode failed: got %s want 198.51.100.20", got)
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

	// 8. Client-spoofed leading XFF behind trusted public relay that appends real client IP:
	//    right-to-left unwinding MUST return 198.51.100.42 (real client), NOT 8.8.8.8 (spoofed)!
	if got := runWS("203.175.12.253", "X-Forwarded-For: 8.8.8.8, 198.51.100.42\r\n", false); got != "198.51.100.42" {
		t.Fatalf("spoofed leading XFF bypassed right-to-left extraction: got %s want 198.51.100.42", got)
	}

	// 9. Multi-header XFF smuggling (client sends first XFF header, trusted relay appends second):
	//    right-to-left across all headers MUST extract 198.51.100.43!
	multiXFF := "X-Forwarded-For: 8.8.8.8\r\nX-Forwarded-For: 198.51.100.43, 172.64.15.9\r\n"
	if got := runWS("203.175.12.253", multiXFF, false); got != "198.51.100.43" {
		t.Fatalf("multi-header XFF with trusted CDN hop failed: got %s want 198.51.100.43", got)
	}

	// 10. Garbage prefix in XFF followed by real client IP appended by trusted relay:
	if got := runWS("203.175.12.253", "X-Forwarded-For: garbage, 198.51.100.44\r\n", false); got != "198.51.100.44" {
		t.Fatalf("garbage-prefixed XFF failed: got %s want 198.51.100.44", got)
	}

	// 11. Malformed CF-Connecting-IP on Cloudflare edge falls through cleanly:
	//     - Without XFF: falls back to valid X-Real-IP
	if got := runWS("172.64.15.9", "CF-Connecting-IP: not-an-ip\r\nX-Real-IP: 198.51.100.45\r\n", false); got != "198.51.100.45" {
		t.Fatalf("malformed CF-Connecting-IP did not fall back to X-Real-IP: got %s want 198.51.100.45", got)
	}
	//     - With XFF: prefers right-to-left XFF over client-spoofable X-Real-IP
	if got := runWS("172.64.15.9", "CF-Connecting-IP: not-an-ip\r\nX-Real-IP: 8.8.8.8\r\nX-Forwarded-For: 8.8.4.4, 198.51.100.46\r\n", false); got != "198.51.100.46" {
		t.Fatalf("malformed CF-Connecting-IP with XFF should prefer XFF over spoofable X-Real-IP: got %s want 198.51.100.46", got)
	}

	// 12. All-private XFF chain behind loopback proxy falls back to leftmost valid private client IP:
	if got := runWS("127.0.0.1", "X-Forwarded-For: 10.0.0.50, 127.0.0.1\r\n", false); got != "10.0.0.50" {
		t.Fatalf("all-private XFF fallback failed: got %s want 10.0.0.50", got)
	}

	// 13. HAProxy L7 relay (`mode http` + `option forwardfor`, does NOT strip CF-Connecting-IP or X-Real-IP):
	//     Attacker sends CF-Connecting-IP, X-Real-IP, and leading XFF; HAProxy appends real attacker IP 198.51.100.88.
	//     BOTH public relay (203.175.12.253) AND local loopback HAProxy (127.0.0.1) MUST return 198.51.100.88!
	haproxySpoofHdrs := "CF-Connecting-IP: 198.51.100.77\r\nX-Real-IP: 198.51.100.77\r\nX-Forwarded-For: 198.51.100.77\r\nX-Forwarded-For: 198.51.100.88\r\n"
	if got := runWS("203.175.12.253", haproxySpoofHdrs, false); got != "198.51.100.88" {
		t.Fatalf("public HAProxy relay vulnerable to CF-Connecting-IP/X-Real-IP spoofing: got %s want 198.51.100.88", got)
	}
	if got := runWS("127.0.0.1", haproxySpoofHdrs, false); got != "198.51.100.88" {
		t.Fatalf("local HAProxy relay vulnerable to CF-Connecting-IP/X-Real-IP spoofing: got %s want 198.51.100.88", got)
	}

	// 14. Public non-Cloudflare relay MUST NOT trust CF-Connecting-IP alone (when XFF and X-Real-IP are absent):
	if got := runWS("203.175.12.253", "CF-Connecting-IP: 198.51.100.77\r\n", false); got != "203.175.12.253" {
		t.Fatalf("public non-Cloudflare relay trusted spoofed CF-Connecting-IP without XFF: got %s want 203.175.12.253", got)
	}

	// 15. Public non-Cloudflare relay with completely malformed XFF MUST NOT fall back to spoofed X-Real-IP or CF-Connecting-IP:
	if got := runWS("203.175.12.253", "CF-Connecting-IP: 198.51.100.77\r\nX-Real-IP: 198.51.100.77\r\nX-Forwarded-For: garbage\r\n", false); got != "203.175.12.253" {
		t.Fatalf("malformed XFF on non-CF relay fell back to spoofable header: got %s want 203.175.12.253", got)
	}

	// 16. Local Nginx (X-Real-IP only, no XFF) beats spoofed CF-Connecting-IP; local cloudflared (CF-Connecting-IP only) still works!
	if got := runWS("127.0.0.1", "CF-Connecting-IP: 8.8.8.8\r\nX-Real-IP: 198.51.100.56\r\n", false); got != "198.51.100.56" {
		t.Fatalf("local Nginx X-Real-IP-only should beat spoofed CF-Connecting-IP: got %s want 198.51.100.56", got)
	}
	if got := runWS("127.0.0.1", "CF-Connecting-IP: 198.51.100.57\r\n", false); got != "198.51.100.57" {
		t.Fatalf("local cloudflared CF-Connecting-IP-only failed: got %s want 198.51.100.57", got)
	}

	// 17. Chained Cloudflare -> HAProxy -> xoga:
	//     a) Trusted Cloudflare hop in XFF without untrusted client token falls back to genuine CF-Connecting-IP!
	if got := runWS("203.175.12.253", "CF-Connecting-IP: 198.51.100.61\r\nX-Forwarded-For: 172.64.15.9\r\n", false); got != "198.51.100.61" {
		t.Fatalf("chained CF->HAProxy CF-Connecting-IP fallback failed: got %s want 198.51.100.61", got)
	}
	//     b) Direct attacker -> HAProxy spoofing BOTH CF-Connecting-IP AND XFF containing a Cloudflare IP:
	//        HAProxy appends real attacker IP 198.51.100.92 at rightmost position -> MUST return 198.51.100.92!
	chainSpoof := "CF-Connecting-IP: 198.51.100.61\r\nX-Forwarded-For: 198.51.100.61, 172.64.15.9, 198.51.100.92\r\n"
	if got := runWS("203.175.12.253", chainSpoof, false); got != "198.51.100.92" {
		t.Fatalf("direct attacker spoofed chained CF->HAProxy via fake CF hop in XFF: got %s want 198.51.100.92", got)
	}

	// 18. Explicit header modes never fall back to unconfigured headers when the configured header is absent:
	if got := runWSWithMode("203.175.12.253", "CF-Connecting-IP: 198.51.100.77\r\nX-Real-IP: 198.51.100.78\r\n", false, ForwardedIPHeaderXFF); got != "203.175.12.253" {
		t.Fatalf("explicit x-forwarded-for mode leaked fallback header: got %s want 203.175.12.253", got)
	}
	if got := runWSWithMode("203.175.12.253", "CF-Connecting-IP: 198.51.100.77\r\nX-Forwarded-For: 198.51.100.78\r\n", false, ForwardedIPHeaderXRealIP); got != "203.175.12.253" {
		t.Fatalf("explicit x-real-ip mode leaked fallback header: got %s want 203.175.12.253", got)
	}
	if got := runWSWithMode("203.175.12.253", "CF-Connecting-IP: 198.51.100.79\r\nX-Forwarded-For: 198.51.100.78\r\n", false, ForwardedIPHeaderCF); got != "198.51.100.79" {
		t.Fatalf("explicit cf-connecting-ip mode failed: got %s want 198.51.100.79", got)
	}
	if got := runWSWithMode("172.64.15.9", "X-Forwarded-For: 198.51.100.78\r\nX-Real-IP: 198.51.100.79\r\n", false, ForwardedIPHeaderCF); got != "172.64.15.9" {
		t.Fatalf("explicit cf-connecting-ip mode leaked fallback header: got %s want 172.64.15.9", got)
	}

	// 19. IPv4-mapped IPv6 Cloudflare peer (::ffff:172.64.15.9 on dual-stack listener) still recognized as Cloudflare:
	if got := runWS("::ffff:172.64.15.9", "X-Forwarded-For: 198.51.100.1\r\nCF-Connecting-IP: 198.51.100.62\r\n", false); got != "198.51.100.62" {
		t.Fatalf("v4-in-v6 Cloudflare peer did not trust CF-Connecting-IP: got %s want 198.51.100.62", got)
	}

	// 20. Transit HAProxy (trusted 203.175.12.253) -> Cloudflare CDN (172.64.15.9) -> xoga:
	//     Cloudflare sets CF-Connecting-IP to the transit HAProxy IP (203.175.12.253) and appends it to XFF.
	//     Because 203.175.12.253 is itself a trusted proxy, auto mode MUST unwind XFF right-to-left to the
	//     real client IP (198.51.100.63) instead of collapsing all users onto 203.175.12.253, while blocking
	//     client-spoofed leading XFF tokens (8.8.8.8).
	if got := runWS("172.64.15.9",
		"CF-Connecting-IP: 203.175.12.253\r\nX-Forwarded-For: 8.8.8.8, 198.51.100.63, 203.175.12.253\r\n", false); got != "198.51.100.63" {
		t.Fatalf("Transit HAProxy -> Cloudflare unwinding failed: got %s want 198.51.100.63", got)
	}
	//     When XFF is absent in Transit HAProxy -> Cloudflare, fall back safely to CF-Connecting-IP (203.175.12.253):
	if got := runWS("172.64.15.9", "CF-Connecting-IP: 203.175.12.253\r\n", false); got != "203.175.12.253" {
		t.Fatalf("Transit HAProxy -> Cloudflare without XFF fallback failed: got %s want 203.175.12.253", got)
	}

	// 21. RFC 9110 §5.1 HTTP header-name whitespace & obs-fold smuggling MUST NOT overwrite trusted headers
	//     or inject trailing X-Forwarded-For tokens:
	if got := runWS("172.64.15.9", "CF-Connecting-IP: 198.51.100.99\r\nCF-Connecting-IP : 198.51.100.77\r\n", false); got != "198.51.100.99" {
		t.Fatalf("whitespace before colon smuggled CF-Connecting-IP: got %s want 198.51.100.99", got)
	}
	if got := runWS("172.64.15.9", "CF-Connecting-IP: 198.51.100.99\r\n CF-Connecting-IP: 198.51.100.77\r\n", false); got != "198.51.100.99" {
		t.Fatalf("obs-fold leading space smuggled CF-Connecting-IP: got %s want 198.51.100.99", got)
	}
	if got := runWS("203.175.12.253", "X-Real-IP: 198.51.100.99\r\nX-Real-IP\t: 198.51.100.77\r\n", false); got != "198.51.100.99" {
		t.Fatalf("tab before colon smuggled X-Real-IP: got %s want 198.51.100.99", got)
	}
	if got := runWS("203.175.12.253", "X-Forwarded-For: 198.51.100.99\r\nX-Forwarded-For : 198.51.100.77\r\n", false); got != "198.51.100.99" {
		t.Fatalf("whitespace before colon smuggled trailing X-Forwarded-For: got %s want 198.51.100.99", got)
	}

	// 22. Invalid/unusable forwarded IP literals (0.0.0.0, ::, ::ffff:0.0.0.0, multicast, zoned IPv6,
	//     unbalanced brackets) MUST be rejected and never trusted (or allow walking past them in XFF):
	for _, bad := range []string{"0.0.0.0", "::", "::ffff:0.0.0.0", "224.0.0.1", "ff02::1", "fe80::1%eth0", "[198.51.100.1", "]198.51.100.1["} {
		if got := runWS("203.175.12.253", "X-Forwarded-For: 198.51.100.77, "+bad+"\r\n", false); got != "203.175.12.253" {
			t.Fatalf("invalid XFF token %q was accepted or walked past: got %s want 203.175.12.253", bad, got)
		}
		if got := runWS("172.64.15.9", "CF-Connecting-IP: "+bad+"\r\n", false); got != "172.64.15.9" {
			t.Fatalf("invalid CF-Connecting-IP %q was accepted: got %s want 172.64.15.9", bad, got)
		}
	}
	//     Valid bracketed IPv6 literal and host:port remain accepted:
	if got := runWS("203.175.12.253", "X-Forwarded-For: [2001:db8::9]:54321\r\n", false); got != "2001:db8::9" {
		t.Fatalf("valid bracketed IPv6 host:port rejected: got %s want 2001:db8::9", got)
	}
	if got := runWS("203.175.12.253", "X-Real-IP: [2001:db8::10]\r\n", false); got != "2001:db8::10" {
		t.Fatalf("valid bracketed IPv6 rejected: got %s want 2001:db8::10", got)
	}
}

func TestZeroConfigLocalAndTrustAllCloudflareChaining(t *testing.T) {
	runWithCIDRs := func(peerIP, extraHeaders string, trustAll bool, cidrs []string, mode ForwardedIPHeaderMode) string {
		t.Helper()
		prefixes, _ := ParseTrustedProxyCIDRs(cidrs)
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
		ws, err := AcceptWebSocketWithTrustedProxies(fc, "/ws", trustAll, prefixes, mode)
		if err != nil {
			t.Fatalf("AcceptWebSocketWithTrustedProxies failed: %v", err)
		}
		defer ws.Close()
		return ws.RemoteAddr().(*net.TCPAddr).IP.String()
	}

	// 1. Zero-config Cloudflare -> local Nginx/Caddy/HAProxy (127.0.0.1, trusted_proxy_cidrs empty)
	//    MUST still extract real client IP 198.51.100.42 instead of collapsing onto Cloudflare edge 172.64.15.9!
	cfLocalHdrs := "CF-Connecting-IP: 198.51.100.42\r\nX-Real-IP: 172.64.15.9\r\nX-Forwarded-For: 8.8.8.8, 198.51.100.42, 172.64.15.9\r\n"
	if got := runWithCIDRs("127.0.0.1", cfLocalHdrs, false, nil, ForwardedIPHeaderAuto); got != "198.51.100.42" {
		t.Fatalf("zero-config Cloudflare->local proxy broke: got %s want 198.51.100.42", got)
	}
	//    Anti-spoofing: direct attacker (198.51.100.92) -> local HAProxy (127.0.0.1, empty trusted_proxy_cidrs)
	//    spoofing CF-Connecting-IP and a fake Cloudflare hop still has real 198.51.100.92 appended rightmost -> blocked!
	localSpoof := "CF-Connecting-IP: 198.51.100.77\r\nX-Forwarded-For: 198.51.100.77, 172.64.15.9, 198.51.100.92\r\n"
	if got := runWithCIDRs("127.0.0.1", localSpoof, false, nil, ForwardedIPHeaderAuto); got != "198.51.100.92" {
		t.Fatalf("zero-config local proxy allowed spoofed Cloudflare hop: got %s want 198.51.100.92", got)
	}

	// 2. Legacy trust_forwarded_ip=true (empty trusted_proxy_cidrs) with Cloudflare -> HAProxy -> xoga:
	//    skips Cloudflare hop 172.64.15.9 and extracts 198.51.100.42 while still blocking direct spoofers!
	if got := runWithCIDRs("203.175.12.253", cfLocalHdrs, true, nil, ForwardedIPHeaderAuto); got != "198.51.100.42" {
		t.Fatalf("trust_forwarded_ip=true Cloudflare->HAProxy broke: got %s want 198.51.100.42", got)
	}
	if got := runWithCIDRs("203.175.12.253", localSpoof, true, nil, ForwardedIPHeaderAuto); got != "198.51.100.92" {
		t.Fatalf("trust_forwarded_ip=true allowed spoofed Cloudflare hop behind HAProxy: got %s want 198.51.100.92", got)
	}

	// 3. Explicit trusted_proxy_cidrs=[203.175.12.253/32] WITHOUT cloudflare strictly enforces the CIDR allowlist
	//    and does NOT skip unconfigured Cloudflare hops in XFF:
	if got := runWithCIDRs("203.175.12.253", cfLocalHdrs, false, []string{"203.175.12.253/32"}, ForwardedIPHeaderAuto); got != "172.64.15.9" {
		t.Fatalf("explicit CIDR allowlist without cloudflare unexpectedly skipped CF hop: got %s want 172.64.15.9", got)
	}
}

func TestParseTrustedProxyCIDRsCloudflareShorthandAndHeaderModes(t *testing.T) {
	prefixes, invalid := ParseTrustedProxyCIDRs([]string{"203.175.12.253", "Cloudflare"})
	if len(invalid) != 0 {
		t.Fatalf("unexpected invalid entries: %v", invalid)
	}
	wantCount := 1 + len(cloudflareIPv4CIDRs) + len(cloudflareIPv6CIDRs)
	if len(prefixes) != wantCount {
		t.Fatalf("expected %d prefixes for relay+cloudflare, got %d", wantCount, len(prefixes))
	}
	if !isTrustedProxyPeer(&net.TCPAddr{IP: net.ParseIP("104.16.1.1"), Port: 1234}, prefixes) {
		t.Fatal("expected Cloudflare IPv4 104.16.1.1 to match cloudflare shorthand")
	}
	if !isTrustedProxyPeer(&net.TCPAddr{IP: net.ParseIP("2606:4700::1"), Port: 1234}, prefixes) {
		t.Fatal("expected Cloudflare IPv6 2606:4700::1 to match cloudflare shorthand")
	}
	// Verify Cloudflare CIDRs are NEVER trusted when not configured
	if isTrustedProxyPeer(&net.TCPAddr{IP: net.ParseIP("172.64.15.9"), Port: 1234}, nil) {
		t.Fatal("Cloudflare peer must NOT be trusted when trusted_proxy_cidrs is empty")
	}

	cases := []struct {
		raw  string
		want ForwardedIPHeaderMode
		ok   bool
	}{
		{"", ForwardedIPHeaderAuto, true},
		{"auto", ForwardedIPHeaderAuto, true},
		{"AUTO", ForwardedIPHeaderAuto, true},
		{"x-forwarded-for", ForwardedIPHeaderXFF, true},
		{"xff", ForwardedIPHeaderXFF, true},
		{"x-real-ip", ForwardedIPHeaderXRealIP, true},
		{"cf-connecting-ip", ForwardedIPHeaderCF, true},
		{"invalid-header", ForwardedIPHeaderAuto, false},
	}
	for _, tc := range cases {
		got, ok := ParseForwardedIPHeaderMode(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("ParseForwardedIPHeaderMode(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}
