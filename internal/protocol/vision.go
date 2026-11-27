package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"unsafe"

	"github.com/xtls/reality"
)

const (
	FlowVision       = "xtls-rprx-vision"
	FlowVisionUDP443 = "xtls-rprx-vision-udp443"

	visionCmdContinue byte = 0x00
	visionCmdEnd      byte = 0x01
	visionCmdDirect   byte = 0x02
)

// decodeVLESSAddonFlow parses the VLESS header Addons protobuf (`message Addons { string Flow = 1; }`)
// without pulling in a heavy protobuf runtime dependency.
func decodeVLESSAddonFlow(raw []byte) string {
	pos := 0
	for pos < len(raw) {
		tag, n := readProtoVarint(raw[pos:])
		if n <= 0 {
			return ""
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 0x07
		switch wireType {
		case 0: // varint
			_, vn := readProtoVarint(raw[pos:])
			if vn <= 0 {
				return ""
			}
			pos += vn
		case 2: // length-delimited
			l, ln := readProtoVarint(raw[pos:])
			if ln <= 0 || l > uint64(len(raw)-pos-ln) {
				return ""
			}
			pos += ln
			val := raw[pos : pos+int(l)]
			pos += int(l)
			if fieldNum == 1 {
				return string(val)
			}
		default:
			return ""
		}
	}
	return ""
}

func readProtoVarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, c := range b {
		if i >= 10 {
			return 0, -1
		}
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, -1
}

// visionConn implements Xray `xtls-rprx-vision` inner handshake padding/unpadding and
// zero-overhead direct raw-TCP unwrapping once inner TLS 1.3 Application Data starts.
type visionConn struct {
	net.Conn
	userUUID [16]byte

	readMu        sync.Mutex
	reader        io.Reader
	withinPadding bool
	checkedInit   bool
	initHdr       [21]byte
	initRead      int
	needNextBlock bool
	remContent    int
	remPadding    int
	curCmd        byte
	hdrBuf        [5]byte
	hdrRead       int
	leftover      []byte

	writeMu           sync.Mutex
	sentVLESSResp     bool
	writePadding      bool
	wroteUUID         bool
	packetsFiltered   int
	innerIsTLS        bool
	innerTLS13AppSeen bool
}

func newVisionConn(conn net.Conn, br io.Reader, userUUID [16]byte) *visionConn {
	if br == nil {
		br = conn
	}
	return &visionConn{
		Conn:          conn,
		userUUID:      userUUID,
		reader:        br,
		withinPadding: true,
		writePadding:  true,
	}
}

func (v *visionConn) NetConn() net.Conn {
	return v.Conn
}

func (v *visionConn) CanHalfCloseWrite() bool {
	if hc, ok := v.Conn.(interface{ CanHalfCloseWrite() bool }); ok {
		return hc.CanHalfCloseWrite()
	}
	_, ok := v.Conn.(interface{ CloseWrite() error })
	return ok
}

func (v *visionConn) CloseWrite() error {
	if cw, ok := v.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

func (v *visionConn) FlushResponseHeader() error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	if !v.sentVLESSResp {
		v.sentVLESSResp = true
		var out [23]byte
		pos := copy(out[:], []byte{0x00, 0x00})
		if v.writePadding && !v.wroteUUID {
			v.wroteUUID = true
			v.writePadding = false
			pos += copy(out[pos:], v.userUUID[:])
			out[pos] = visionCmdEnd
			pos += 5
		}
		return writeAllConn(v.Conn, out[:pos])
	}
	return nil
}

func isVisionTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (v *visionConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	v.readMu.Lock()
	defer v.readMu.Unlock()

	for {
		if len(v.leftover) > 0 {
			n := copy(p, v.leftover)
			v.leftover = v.leftover[n:]
			return n, nil
		}

		if !v.checkedInit {
			for v.initRead < 21 {
				n, err := v.reader.Read(v.initHdr[v.initRead:21])
				v.initRead += n
				if err != nil {
					if isVisionTimeout(err) {
						// Preserve `checkedInit = false` & `initRead` across 150ms SNI peek timeouts!
						return 0, err
					}
					v.checkedInit = true
					if v.initRead > 0 {
						v.withinPadding = false
						nc := copy(p, v.initHdr[:v.initRead])
						if nc < v.initRead {
							v.leftover = append(v.leftover[:0], v.initHdr[nc:v.initRead]...)
						}
						return nc, nil
					}
					return 0, err
				}
			}
			v.checkedInit = true
			if bytes.Equal(v.initHdr[:16], v.userUUID[:]) {
				v.curCmd = v.initHdr[16]
				v.remContent = int(binary.BigEndian.Uint16(v.initHdr[17:19]))
				v.remPadding = int(binary.BigEndian.Uint16(v.initHdr[19:21]))
				v.withinPadding = true
			} else {
				v.withinPadding = false
				nc := copy(p, v.initHdr[:21])
				if nc < 21 {
					v.leftover = append(v.leftover[:0], v.initHdr[nc:21]...)
				}
				return nc, nil
			}
		}

		if !v.withinPadding {
			return v.reader.Read(p)
		}

		if v.needNextBlock {
			if err := v.finishReadBlockLocked(); err != nil {
				return 0, err
			}
			v.needNextBlock = false
			continue
		}

		if v.remContent > 0 {
			toRead := len(p)
			if toRead > v.remContent {
				toRead = v.remContent
			}
			n, err := v.reader.Read(p[:toRead])
			v.remContent -= n
			if v.remContent == 0 && v.remPadding == 0 {
				if v.curCmd == visionCmdContinue {
					// Defer reading the next 5-byte Vision header until the next Read() call
					// so `n` payload bytes (e.g. ClientHello) are returned immediately without blocking!
					v.needNextBlock = true
				} else if finErr := v.finishReadBlockLocked(); finErr != nil && n == 0 {
					return 0, finErr
				}
			}
			if n > 0 {
				return n, nil
			}
			if err != nil {
				return 0, err
			}
			continue
		}

		if v.remPadding > 0 {
			nPad, err := io.CopyN(io.Discard, v.reader, int64(v.remPadding))
			v.remPadding -= int(nPad)
			if err != nil {
				return 0, err
			}
		}

		if err := v.finishReadBlockLocked(); err != nil {
			return 0, err
		}
	}
}

func (v *visionConn) finishReadBlockLocked() error {
	switch v.curCmd {
	case visionCmdContinue:
		for v.hdrRead < 5 {
			n, err := v.reader.Read(v.hdrBuf[v.hdrRead:5])
			v.hdrRead += n
			if err != nil {
				return err
			}
		}
		v.hdrRead = 0
		v.curCmd = v.hdrBuf[0]
		v.remContent = int(binary.BigEndian.Uint16(v.hdrBuf[1:3]))
		v.remPadding = int(binary.BigEndian.Uint16(v.hdrBuf[3:5]))
		return nil
	case visionCmdEnd:
		v.withinPadding = false
		return nil
	case visionCmdDirect:
		v.withinPadding = false
		v.switchToDirectReaderLocked()
		return nil
	default:
		v.withinPadding = false
		return nil
	}
}

// switchToDirectReaderLocked drains any buffered bytes in `bufio.Reader` and the outer
// `*reality.Conn` / `*tls.Conn` (`input` + `rawInput`) before switching directly to the
// underlying raw TCP connection, matching Xray `VisionReader` `CommandPaddingDirect (2)`.
func (v *visionConn) switchToDirectReaderLocked() {
	var drained bytes.Buffer
	if br, ok := v.reader.(interface{ Buffered() int }); ok && br.Buffered() > 0 {
		_, _ = io.CopyN(&drained, v.reader, int64(br.Buffered()))
	}
	rawConn, extra := extractOuterTLSBuffered(v.Conn)
	if len(extra) > 0 {
		_, _ = drained.Write(extra)
	}
	if rawConn != nil {
		if drained.Len() > 0 {
			v.reader = io.MultiReader(bytes.NewReader(drained.Bytes()), rawConn)
		} else {
			v.reader = rawConn
		}
	} else if drained.Len() > 0 {
		v.reader = io.MultiReader(bytes.NewReader(drained.Bytes()), v.Conn)
	}
}

func extractOuterTLSBuffered(c net.Conn) (net.Conn, []byte) {
	switch tc := c.(type) {
	case *reality.Conn:
		extra := drainTLSStructBuffers(reflect.ValueOf(tc).Elem())
		return tc.NetConn(), extra
	case *tls.Conn:
		extra := drainTLSStructBuffers(reflect.ValueOf(tc).Elem())
		return tc.NetConn(), extra
	default:
		return nil, nil
	}
}

func drainTLSStructBuffers(val reflect.Value) []byte {
	if !val.IsValid() || val.Kind() != reflect.Struct {
		return nil
	}
	var out bytes.Buffer
	if f := val.FieldByName("input"); f.IsValid() && f.CanAddr() && f.Type() == reflect.TypeOf(bytes.Reader{}) {
		rd := (*bytes.Reader)(unsafe.Pointer(f.UnsafeAddr()))
		if rd.Len() > 0 {
			_, _ = io.Copy(&out, rd)
		}
	}
	if f := val.FieldByName("rawInput"); f.IsValid() {
		if f.Kind() == reflect.Ptr && !f.IsNil() && f.Type() == reflect.TypeOf((*bytes.Buffer)(nil)) {
			buf := (*bytes.Buffer)(unsafe.Pointer(f.Pointer()))
			if buf.Len() > 0 {
				_, _ = out.Write(buf.Bytes())
				buf.Reset()
			}
		} else if f.CanAddr() && f.Type() == reflect.TypeOf(bytes.Buffer{}) {
			buf := (*bytes.Buffer)(unsafe.Pointer(f.UnsafeAddr()))
			if buf.Len() > 0 {
				_, _ = out.Write(buf.Bytes())
				buf.Reset()
			}
		}
	}
	return out.Bytes()
}

func (v *visionConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	v.writeMu.Lock()
	defer v.writeMu.Unlock()

	var prefix []byte
	if !v.sentVLESSResp {
		v.sentVLESSResp = true
		prefix = []byte{0x00, 0x00}
	}

	if !v.writePadding {
		if len(prefix) > 0 {
			bufs := net.Buffers{prefix, p}
			if _, err := bufs.WriteTo(v.Conn); err != nil {
				return 0, err
			}
			return len(p), nil
		}
		return v.Conn.Write(p)
	}

	// Inspect inner TLS records (scanning across coalesced ServerHello + CCS + EncryptedExtensions records)
	if v.packetsFiltered < 8 {
		v.packetsFiltered++
		scanInnerTLSRecords(p, &v.innerIsTLS, &v.innerTLS13AppSeen)
	}

	total := 0
	rem := p
	const maxVisionChunk = 8192 - 21 - 16
	for len(rem) > 0 {
		chunk := rem
		if len(chunk) > maxVisionChunk {
			chunk = rem[:maxVisionChunk]
		}
		rem = rem[len(chunk):]

		isLast := len(rem) == 0
		cmd := visionCmdContinue
		if isLast && (v.innerTLS13AppSeen || (!v.innerIsTLS && v.packetsFiltered >= 6) || v.packetsFiltered >= 8) {
			// Send CommandPaddingEnd (1) so client cleanly exits Vision unpadding mode while continuing encrypted framing
			cmd = visionCmdEnd
			v.writePadding = false
		}

		padLen := computeVisionPaddingLen(len(chunk), v.innerIsTLS && cmd == visionCmdContinue)
		frameLen := len(prefix) + 5 + len(chunk) + padLen
		if !v.wroteUUID {
			frameLen += 16
		}
		frame := make([]byte, frameLen)
		pos := 0
		if len(prefix) > 0 {
			pos += copy(frame[pos:], prefix)
			prefix = nil
		}
		if !v.wroteUUID {
			v.wroteUUID = true
			pos += copy(frame[pos:], v.userUUID[:])
		}
		frame[pos] = cmd
		binary.BigEndian.PutUint16(frame[pos+1:pos+3], uint16(len(chunk)))
		binary.BigEndian.PutUint16(frame[pos+3:pos+5], uint16(padLen))
		pos += 5
		pos += copy(frame[pos:], chunk)
		if padLen > 0 {
			_, _ = rand.Read(frame[pos : pos+padLen])
		}

		if err := writeAllConn(v.Conn, frame); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func scanInnerTLSRecords(b []byte, innerIsTLS, innerAppSeen *bool) {
	pos := 0
	for pos+5 <= len(b) {
		ct := b[pos]
		if b[pos+1] != 0x03 || b[pos+2] > 0x04 {
			break
		}
		rlen := int(binary.BigEndian.Uint16(b[pos+3 : pos+5]))
		if ct == 0x16 {
			*innerIsTLS = true
		} else if ct == 0x17 && *innerIsTLS && b[pos+2] == 0x03 {
			*innerAppSeen = true
			return
		} else if ct != 0x14 && ct != 0x15 {
			break
		}
		if rlen <= 0 || pos+5+rlen > len(b) {
			break
		}
		pos += 5 + rlen
	}
}

func computeVisionPaddingLen(contentLen int, longPadding bool) int {
	// Default Xray Vision testseed: [900, 500, 900, 256]
	if longPadding && contentLen < 900 {
		r := randIntMax(500)
		pad := r + 900 - contentLen
		if pad < 0 {
			pad = 0
		}
		return pad
	}
	return randIntMax(256)
}

func randIntMax(maxVal int64) int {
	if maxVal <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(maxVal))
	if err != nil {
		return 32
	}
	return int(n.Int64())
}

func writeAllConn(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
