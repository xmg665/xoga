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

// isTrustedProxyPeer reports whether the immediate TCP peer is loopback or private/link-local
// (e.g. local Nginx/HAProxy/Caddy/cloudflared), preventing public clients from spoofing X-Forwarded-For / CF-Connecting-IP.
func isTrustedProxyPeer(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	var ip netip.Addr
	if ta, ok := addr.(*net.TCPAddr); ok {
		if parsed, ok2 := netip.AddrFromSlice(ta.IP); ok2 {
			ip = parsed.Unmap()
		}
	} else if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		if parsed, perr := netip.ParseAddr(host); perr == nil {
			ip = parsed.Unmap()
		}
	}
	return ip.IsValid() && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// AcceptWebSocket performs a zero-dependency RFC 6455 HTTP Upgrade handshake, supports
// Xray/Sing-box `Sec-WebSocket-Protocol` base64url Early Data (`?ed=2048`), and extracts
// real client IPs from CDN/reverse-proxy headers ONLY when the immediate peer is a trusted proxy.
func AcceptWebSocket(c net.Conn, expectedPath string, trustForwarded ...bool) (net.Conn, error) {
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

	var wsKey, wsProto, realIPStr string
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
			realIPStr = v
		case "x-real-ip":
			if realIPStr == "" {
				realIPStr = v
			}
		case "x-forwarded-for":
			if realIPStr == "" {
				first, _, _ := strings.Cut(v, ",")
				realIPStr = strings.TrimSpace(first)
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

	// Decode V2Ray/Xray/Mihomo Early Data from Sec-WebSocket-Protocol if present
	var earlyData []byte
	var echoedProto string
	if wsProto != "" {
		token := wsProto
		if comma := strings.IndexByte(token, ','); comma > 0 {
			token = strings.TrimSpace(token[:comma])
		}
		if decoded, derr := decodeBase64Flexible(token); derr == nil && len(decoded) > 0 {
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
	trustHeaders := (len(trustForwarded) > 0 && trustForwarded[0]) || isTrustedProxyPeer(remoteAddr)
	if trustHeaders && realIPStr != "" {
		if ip := net.ParseIP(realIPStr); ip != nil {
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
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
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

	writeMu sync.Mutex
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

func (w *wsConn) writeControlFrame(opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	_ = w.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = w.Conn.SetWriteDeadline(time.Time{}) }()
	hdr := [2]byte{0x80 | opcode, byte(len(payload))}
	bufs := net.Buffers{hdr[:], payload}
	_, err := bufs.WriteTo(w.rawWriter)
	return err
}
