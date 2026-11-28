package transport

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var wsReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 4096)
	},
}

func unwrapRawWriter(c net.Conn) io.Writer {
	cur := c
	for i := 0; i < 4; i++ {
		if tc, ok := cur.(*net.TCPConn); ok {
			return tc
		}
		// Only unwrap transparent write pass-through wrappers (e.g. proxyProtoConn / PrependConn),
		// NEVER *tls.Conn or *reality.Conn (which also implement NetConn() but must encrypt writes!).
		if w, ok := cur.(interface{ RawWriteConn() net.Conn }); ok {
			next := w.RawWriteConn()
			if next != nil && next != cur {
				cur = next
				continue
			}
		}
		break
	}
	return c
}

func readLimitedWSLine(br *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		frag, isPrefix, err := br.ReadLine()
		if err != nil {
			return "", err
		}
		if len(buf)+len(frag) > maxLen {
			return "", errors.New("websocket HTTP header line too long")
		}
		if !isPrefix && len(buf) == 0 {
			return string(frag), nil
		}
		buf = append(buf, frag...)
		if !isPrefix {
			return string(buf), nil
		}
	}
}

// ParseTrustedProxyCIDRs parses a list of IP addresses or CIDR ranges (e.g. "203.0.113.10" or
// "172.64.0.0/13") into canonical netip.Prefix entries, returning any invalid tokens separately.
func ParseTrustedProxyCIDRs(entries []string) ([]netip.Prefix, []string) {
	if len(entries) == 0 {
		return nil, nil
	}
	var prefixes []netip.Prefix
	var invalid []string
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				invalid = append(invalid, s)
				continue
			}
			addr := pfx.Addr()
			bits := pfx.Bits()
			if addr.Is4In6() {
				addr = addr.Unmap()
				if bits >= 96 {
					bits -= 96
				} else {
					bits = 0
				}
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits).Masked())
			continue
		}
		addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil {
			invalid = append(invalid, s)
			continue
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, invalid
}

func isTrustedProxyAddr(ip netip.Addr, trustedCIDRs []netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, pfx := range trustedCIDRs {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func extractPeerNetIP(addr net.Addr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	if ta, ok := addr.(*net.TCPAddr); ok {
		if parsed, ok2 := netip.AddrFromSlice(ta.IP); ok2 {
			return parsed.Unmap()
		}
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		if parsed, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr == nil {
			return parsed.Unmap()
		}
	}
	return netip.Addr{}
}

// isTrustedProxyPeer reports whether the immediate TCP peer is loopback, private/link-local
// (e.g. local Nginx/HAProxy/Caddy/cloudflared), or inside one of trustedCIDRs (e.g. public
// L7 HTTP relays / Cloudflare CDN ranges), preventing untrusted public clients from spoofing
// X-Forwarded-For / CF-Connecting-IP / X-Real-IP headers.
func isTrustedProxyPeer(addr net.Addr, trustedCIDRs []netip.Prefix) bool {
	return isTrustedProxyAddr(extractPeerNetIP(addr), trustedCIDRs)
}

func parseForwardedClientAddr(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return addr.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func parseForwardedClientIP(raw string) net.IP {
	if addr, ok := parseForwardedClientAddr(raw); ok {
		return net.IP(addr.AsSlice())
	}
	return nil
}

// selectForwardedClientIP extracts the real client IP with strict header priority
// (CF-Connecting-IP > X-Real-IP > X-Forwarded-For), falling through if a higher-priority
// header is malformed. For X-Forwarded-For, tokens across all XFF headers are walked
// right-to-left skipping trusted proxy hops (loopback/private/link-local, trustedCIDRs,
// and the immediate peer IP) so client-injected leading XFF values cannot spoof the IP.
func selectForwardedClientIP(cfIP, xRealIP string, xffTokens []string, peerAddr net.Addr, trustedCIDRs []netip.Prefix) net.IP {
	if ip := parseForwardedClientIP(cfIP); ip != nil {
		return ip
	}
	if ip := parseForwardedClientIP(xRealIP); ip != nil {
		return ip
	}
	if len(xffTokens) == 0 {
		return nil
	}
	peerIP := extractPeerNetIP(peerAddr)
	var leftmostTrusted netip.Addr
	for i := len(xffTokens) - 1; i >= 0; i-- {
		addr, ok := parseForwardedClientAddr(xffTokens[i])
		if !ok {
			// Stop walking past a malformed/untrusted hop so leading spoofed tokens
			// cannot be trusted behind garbage injected by an untrusted client.
			break
		}
		if (peerIP.IsValid() && addr == peerIP) || isTrustedProxyAddr(addr, trustedCIDRs) {
			leftmostTrusted = addr
			continue
		}
		return net.IP(addr.AsSlice())
	}
	if leftmostTrusted.IsValid() {
		return net.IP(leftmostTrusted.AsSlice())
	}
	return nil
}

// AcceptWebSocket performs a zero-dependency RFC 6455 HTTP Upgrade handshake, supports
// Xray/Sing-box `Sec-WebSocket-Protocol` base64url Early Data (`?ed=2048`), and extracts
// real client IPs from CDN/reverse-proxy headers ONLY when the immediate peer is a trusted proxy.
func AcceptWebSocket(c net.Conn, expectedPath string, trustForwarded ...bool) (net.Conn, error) {
	trustAll := len(trustForwarded) > 0 && trustForwarded[0]
	return AcceptWebSocketWithTrustedProxies(c, expectedPath, trustAll, nil)
}

// AcceptWebSocketWithTrustedProxies performs the RFC 6455 WebSocket upgrade and trusts
// CF-Connecting-IP / X-Real-IP / X-Forwarded-For headers when trustAllForwarded is true or
// when the immediate peer is loopback/private/link-local or matches trustedCIDRs.
func AcceptWebSocketWithTrustedProxies(c net.Conn, expectedPath string, trustAllForwarded bool, trustedCIDRs []netip.Prefix) (net.Conn, error) {
	br := wsReaderPool.Get().(*bufio.Reader)
	br.Reset(c)
	reqLine, err := readLimitedWSLine(br, 4096)
	if err != nil {
		br.Reset(nil)
		wsReaderPool.Put(br)
		return nil, err
	}
	parts := strings.Fields(reqLine)
	if len(parts) < 3 || parts[0] != "GET" {
		br.Reset(nil)
		wsReaderPool.Put(br)
		return nil, errors.New("invalid websocket HTTP request line")
	}

	reqPath := parts[1]
	if qIdx := strings.IndexByte(reqPath, '?'); qIdx >= 0 {
		reqPath = reqPath[:qIdx]
	}
	if expectedPath != "" && expectedPath != "/" {
		cleanExp := expectedPath
		if qIdx := strings.IndexByte(cleanExp, '?'); qIdx >= 0 {
			cleanExp = cleanExp[:qIdx]
		}
		if reqPath != cleanExp {
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, errors.New("websocket path mismatch")
		}
	}

	var wsKey, wsProto, cfIP, xRealIP string
	var xffTokens []string
	headerBytes := 0
	for lineCount := 0; ; lineCount++ {
		if lineCount >= 64 {
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, errors.New("too many websocket HTTP headers")
		}
		line, err := readLimitedWSLine(br, 8192)
		if err != nil {
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, err
		}
		headerBytes += len(line)
		if headerBytes > 32768 {
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, errors.New("websocket HTTP headers too large")
		}
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "sec-websocket-key":
			wsKey = v
		case "sec-websocket-protocol":
			wsProto = v
		case "cf-connecting-ip":
			cfIP = v
		case "x-real-ip":
			xRealIP = v
		case "x-forwarded-for":
			for _, part := range strings.Split(v, ",") {
				if tok := strings.TrimSpace(part); tok != "" {
					xffTokens = append(xffTokens, tok)
				}
			}
		}
	}

	if wsKey == "" {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		br.Reset(nil)
		wsReaderPool.Put(br)
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	// Decode V2Ray/Xray/Mihomo Early Data from Sec-WebSocket-Protocol if present.
	// Guard against plain ASCII WebSocket subprotocol tokens (e.g. "chat", "binary",
	// "graphql-ws") which happen to consist of valid base64 characters and would
	// otherwise inject garbage bytes before the proxy handshake.
	var earlyData []byte
	var echoedProto string
	if wsProto != "" {
		token := wsProto
		if comma := strings.IndexByte(token, ','); comma > 0 {
			token = strings.TrimSpace(token[:comma])
		}
		if decoded, derr := decodeBase64Flexible(token); derr == nil && isLikelyWSEarlyData(token, decoded) {
			earlyData = decoded
			echoedProto = token
		}
	}

	h := sha1.New()
	h.Write([]byte(wsKey))
	h.Write([]byte(wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var resp strings.Builder
	resp.Grow(192)
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	resp.WriteString(accept)
	resp.WriteString("\r\n")
	if echoedProto != "" {
		resp.WriteString("Sec-WebSocket-Protocol: ")
		resp.WriteString(echoedProto)
		resp.WriteString("\r\n")
	}
	resp.WriteString("\r\n")
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(resp.String())); err != nil {
		br.Reset(nil)
		wsReaderPool.Put(br)
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})

	remoteAddr := c.RemoteAddr()
	trustHeaders := trustAllForwarded || isTrustedProxyPeer(remoteAddr, trustedCIDRs)
	if trustHeaders {
		if ip := selectForwardedClientIP(cfIP, xRealIP, xffTokens, remoteAddr, trustedCIDRs); ip != nil {
			port := 0
			if ta, ok := remoteAddr.(*net.TCPAddr); ok {
				port = ta.Port
			}
			remoteAddr = &net.TCPAddr{IP: ip, Port: port}
		}
	}

	return &wsConn{
		Conn:       c,
		rawWriter:  unwrapRawWriter(c),
		br:         br,
		remoteAddr: remoteAddr,
		pending:    earlyData,
	}, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if len(s) == 0 {
		return nil, errors.New("empty base64 token")
	}
	if b, err := base64.RawURLEncoding.Strict().DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

// isLikelyWSEarlyData distinguishes real Xray/sing-box/Mihomo base64 early-data
// payloads (>=16 bytes of VMess/VLESS/Trojan/SS handshake) from plain ASCII
// RFC 6455 subprotocol names such as "chat", "binary", or "graphql-transport-ws".
func isLikelyWSEarlyData(token string, decoded []byte) bool {
	if len(decoded) < 16 {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '+' || c == '/' || c == '=' {
			return true
		}
	}
	return false
}

type wsConn struct {
	net.Conn
	rawWriter  io.Writer // unwrapped *net.TCPConn when available so net.Buffers hits kernel writev(2)!
	br         *bufio.Reader
	remoteAddr net.Addr
	closeOnce  sync.Once

	readMu      sync.Mutex
	pending     []byte
	frameRem    int64
	maskKey     [4]byte
	masked      bool
	maskPos     int
	hdrBuf      [14]byte // preserves partial WS frame header across read timeouts
	hdrRead     int
	ctrlOp      byte // 0=none, 0x9=ping, 0xFF=discard
	ctrlRem     int64
	ctrlMasked  bool
	ctrlMaskKey [4]byte
	ctrlBuf     [125]byte
	ctrlRead    int

	writeMu       sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func (w *wsConn) IsBufferedStream() bool { return true }

func (w *wsConn) NetConn() net.Conn { return w.Conn }

func (w *wsConn) Close() error {
	err := w.Conn.Close()
	w.closeOnce.Do(func() {
		w.readMu.Lock()
		if w.br != nil {
			w.br.Reset(nil)
			wsReaderPool.Put(w.br)
			w.br = nil
		}
		w.readMu.Unlock()
	})
	return err
}

func (w *wsConn) RemoteAddr() net.Addr {
	if w.remoteAddr != nil {
		return w.remoteAddr
	}
	return w.Conn.RemoteAddr()
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()

	if len(w.pending) > 0 {
		n := copy(p, w.pending)
		w.pending = w.pending[n:]
		return n, nil
	}

	if w.br == nil {
		return 0, io.EOF
	}
	for w.frameRem == 0 {
		if w.ctrlOp != 0 {
			if w.ctrlOp == 0x9 {
				for w.ctrlRem > 0 {
					n, err := w.br.Read(w.ctrlBuf[w.ctrlRead : w.ctrlRead+int(w.ctrlRem)])
					w.ctrlRead += n
					w.ctrlRem -= int64(n)
					if w.ctrlRem <= 0 {
						break
					}
					if err != nil {
						return 0, err
					}
				}
				pingData := w.ctrlBuf[:w.ctrlRead]
				if w.ctrlMasked {
					for i := range pingData {
						pingData[i] ^= w.ctrlMaskKey[i&3]
					}
				}
				w.ctrlOp = 0
				w.ctrlRead = 0
				_ = w.writeControlFrame(0xA, pingData)
				continue
			}
			var discardBuf [256]byte
			for w.ctrlRem > 0 {
				want := int64(len(discardBuf))
				if want > w.ctrlRem {
					want = w.ctrlRem
				}
				n, err := w.br.Read(discardBuf[:want])
				w.ctrlRem -= int64(n)
				if w.ctrlRem <= 0 {
					break
				}
				if err != nil {
					return 0, err
				}
			}
			w.ctrlOp = 0
			continue
		}

		// Preserve partial WS frame header bytes across short read deadlines (e.g. 150ms SNI peek)
		// so a split header can never desynchronize the WebSocket stream.
		for w.hdrRead < 2 {
			n, err := w.br.Read(w.hdrBuf[w.hdrRead:2])
			w.hdrRead += n
			if w.hdrRead >= 2 {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		opcode := w.hdrBuf[0] & 0x0F
		masked := (w.hdrBuf[1] & 0x80) != 0
		lenCode := w.hdrBuf[1] & 0x7F
		need := 2
		if lenCode == 126 {
			need += 2
		} else if lenCode == 127 {
			need += 8
		}
		if masked {
			need += 4
		}
		for w.hdrRead < need {
			n, err := w.br.Read(w.hdrBuf[w.hdrRead:need])
			w.hdrRead += n
			if w.hdrRead >= need {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		w.hdrRead = 0

		pos := 2
		var payLen int64
		switch lenCode {
		case 126:
			payLen = int64(binary.BigEndian.Uint16(w.hdrBuf[pos : pos+2]))
			pos += 2
		case 127:
			payLen = int64(binary.BigEndian.Uint64(w.hdrBuf[pos : pos+8]))
			pos += 8
			if payLen < 0 || payLen > 16*1024*1024 {
				return 0, errors.New("websocket frame too large")
			}
		default:
			payLen = int64(lenCode)
		}

		if opcode >= 0x8 && payLen > 125 {
			return 0, errors.New("websocket control frame exceeds 125 bytes")
		}

		var mkey [4]byte
		if masked {
			copy(mkey[:], w.hdrBuf[pos:pos+4])
		}

		switch opcode {
		case 0x0, 0x1, 0x2: // continuation, text, binary
			w.frameRem = payLen
			w.masked = masked
			w.maskKey = mkey
			w.maskPos = 0
		case 0x8: // close
			return 0, io.EOF
		case 0x9: // ping -> reply pong
			if payLen == 0 {
				_ = w.writeControlFrame(0xA, nil)
			} else {
				w.ctrlOp = 0x9
				w.ctrlRem = payLen
				w.ctrlMasked = masked
				w.ctrlMaskKey = mkey
				w.ctrlRead = 0
			}
		default: // pong (0xA) and unknown opcodes -> discard payload
			if payLen > 0 {
				w.ctrlOp = 0xFF
				w.ctrlRem = payLen
			}
		}
	}

	toRead := int64(len(p))
	if toRead > w.frameRem {
		toRead = w.frameRem
	}
	n, err := w.br.Read(p[:toRead])
	if n > 0 {
		if w.masked {
			w.maskPos = xorMaskBytes(p[:n], w.maskKey, w.maskPos)
		}
		w.frameRem -= int64(n)
	}
	return n, err
}

// xorMaskBytes unmasks/masks WebSocket frame payloads 8 bytes (`uint64`) per iteration
// (gobwas/ws & xray-core style word-aligned masking), ~7x faster than byte-by-byte XOR.
func xorMaskBytes(b []byte, mk [4]byte, mp int) int {
	n := len(b)
	i := 0
	for ; i < n && (mp&3) != 0; i++ {
		b[i] ^= mk[mp&3]
		mp++
	}
	if n-i >= 8 {
		m32 := binary.LittleEndian.Uint32(mk[:])
		m64 := uint64(m32)<<32 | uint64(m32)
		for ; i+8 <= n; i += 8 {
			v := binary.LittleEndian.Uint64(b[i : i+8])
			binary.LittleEndian.PutUint64(b[i:i+8], v^m64)
		}
	}
	for ; i < n; i++ {
		b[i] ^= mk[mp&3]
		mp++
	}
	return mp & 3
}

func (w *wsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	var hdr [10]byte
	hdr[0] = 0x82 // FIN=1, Opcode=2 (binary)
	hdrLen := 2
	n := len(p)
	switch {
	case n < 126:
		hdr[1] = byte(n)
	case n <= 65535:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hdrLen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hdrLen = 10
	}

	// Use net.Buffers (writev / scatter-gather I/O) against unwrapped *net.TCPConn
	// so even under ProxyProtocol (`proxy_protocol=true`), WS header + payload emit in 1 single writev(2) syscall!
	bufs := net.Buffers{hdr[:hdrLen], p}
	if _, err := bufs.WriteTo(w.rawWriter); err != nil {
		return 0, err
	}
	return n, nil
}

// WritePrependWSFrame writes the RFC 6455 binary frame header directly into `buf[payloadOffset-hdrLen:payloadOffset]`
// (caller guarantees `payloadOffset >= 10`) and flushes the contiguous slice in a single `write(2)` syscall
// with zero `net.Buffers` heap escapes or scatter-gather `iovec` overhead.
func (w *wsConn) WritePrependWSFrame(buf []byte, payloadOffset int) error {
	n := len(buf) - payloadOffset
	if n <= 0 {
		return nil
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	var hdrStart int
	switch {
	case n < 126:
		hdrStart = payloadOffset - 2
		buf[hdrStart] = 0x82
		buf[hdrStart+1] = byte(n)
	case n <= 65535:
		hdrStart = payloadOffset - 4
		buf[hdrStart] = 0x82
		buf[hdrStart+1] = 126
		binary.BigEndian.PutUint16(buf[hdrStart+2:payloadOffset], uint16(n))
	default:
		hdrStart = payloadOffset - 10
		buf[hdrStart] = 0x82
		buf[hdrStart+1] = 127
		binary.BigEndian.PutUint64(buf[hdrStart+2:payloadOffset], uint64(n))
	}

	frame := buf[hdrStart:]
	for len(frame) > 0 {
		nw, err := w.rawWriter.Write(frame)
		if err != nil {
			return err
		}
		if nw <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[nw:]
	}
	return nil
}

func (w *wsConn) SetWriteDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	err := w.Conn.SetWriteDeadline(t)
	w.deadlineMu.Unlock()
	return err
}

func (w *wsConn) SetDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	err := w.Conn.SetDeadline(t)
	w.deadlineMu.Unlock()
	return err
}

func (w *wsConn) writeControlFrame(opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	w.deadlineMu.Lock()
	pongDL := time.Now().Add(5 * time.Second)
	if w.writeDeadline.IsZero() || pongDL.Before(w.writeDeadline) {
		_ = w.Conn.SetWriteDeadline(pongDL)
	}
	w.deadlineMu.Unlock()
	defer func() {
		w.deadlineMu.Lock()
		_ = w.Conn.SetWriteDeadline(w.writeDeadline)
		w.deadlineMu.Unlock()
	}()

	hdr := [2]byte{0x80 | opcode, byte(len(payload))}
	bufs := net.Buffers{hdr[:], payload}
	_, err := bufs.WriteTo(w.rawWriter)
	return err
}
