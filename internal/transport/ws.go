package transport

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
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
		if w, ok := cur.(interface{ NetConn() net.Conn }); ok {
			next := w.NetConn()
			if next != nil && next != cur {
				cur = next
				continue
			}
		}
		break
	}
	return c
}

// AcceptWebSocket performs a zero-dependency RFC 6455 HTTP Upgrade handshake, supports
// Xray/Sing-box `Sec-WebSocket-Protocol` base64url Early Data (`?ed=2048`), and extracts
// real client IPs from CDN/reverse-proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).
func AcceptWebSocket(c net.Conn, expectedPath string) (net.Conn, error) {
	br := wsReaderPool.Get().(*bufio.Reader)
	br.Reset(c)
	reqLine, err := br.ReadString('\n')
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
			_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, errors.New("websocket path mismatch")
		}
	}

	var wsKey, wsProto, realIPStr string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			br.Reset(nil)
			wsReaderPool.Put(br)
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
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
	if _, err := c.Write([]byte(resp.String())); err != nil {
		br.Reset(nil)
		wsReaderPool.Put(br)
		return nil, err
	}

	remoteAddr := c.RemoteAddr()
	if realIPStr != "" {
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

	readMu   sync.Mutex
	pending  []byte
	frameRem int64
	maskKey  [4]byte
	masked   bool
	maskPos  int

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
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			return 0, err
		}
		opcode := hdr[0] & 0x0F
		masked := (hdr[1] & 0x80) != 0
		payLen := int64(hdr[1] & 0x7F)

		switch payLen {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return 0, err
			}
			payLen = int64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return 0, err
			}
			payLen = int64(binary.BigEndian.Uint64(ext[:]))
			if payLen < 0 || payLen > 16*1024*1024 {
				return 0, errors.New("websocket frame too large")
			}
		}

		var mkey [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mkey[:]); err != nil {
				return 0, err
			}
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
			pingData := make([]byte, payLen)
			if _, err := io.ReadFull(w.br, pingData); err != nil {
				return 0, err
			}
			if masked {
				for i := range pingData {
					pingData[i] ^= mkey[i&3]
				}
			}
			_ = w.writeControlFrame(0xA, pingData)
		case 0xA: // pong -> discard
			if payLen > 0 {
				_, _ = io.CopyN(io.Discard, w.br, payLen)
			}
		default:
			if payLen > 0 {
				_, _ = io.CopyN(io.Discard, w.br, payLen)
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

func (w *wsConn) writeControlFrame(opcode byte, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	hdr := [2]byte{0x80 | opcode, byte(len(payload))}
	bufs := net.Buffers{hdr[:], payload}
	_, err := bufs.WriteTo(w.rawWriter)
	return err
}
