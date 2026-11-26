package relay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var proxyV2Sig = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ProxyProtoListener wraps a net.Listener and transparently parses HAProxy PROXY Protocol v1 & v2
// headers (`proxy_protocol=true` in soga.conf) so transit/relay nodes preserve real client IPs
// while still exposing the underlying *net.TCPConn for TCP_NODELAY and Linux splice(2) zero-copy.
type ProxyProtoListener struct {
	net.Listener
	RequireHeader bool // when `force_proxy_protocol=true`, reject non-PROXY connections
}

func (l *ProxyProtoListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyProtoConn{Conn: c, requireHdr: l.RequireHeader}, nil
}

type proxyProtoConn struct {
	net.Conn
	requireHdr bool
	parseOnce  sync.Once
	parseErr   error
	remoteAddr net.Addr
	readMu     sync.Mutex
	leftover   []byte
	drained    atomic.Bool
}

func (p *proxyProtoConn) ensureParsed() error {
	p.parseOnce.Do(func() {
		p.parseErr = p.parseHeader()
		if p.parseErr == nil && len(p.leftover) == 0 {
			p.drained.Store(true)
		}
	})
	return p.parseErr
}

// NetConn exposes the wrapped connection so TuneTCP (`SetNoDelay` / `SetKeepAlive`) works through ProxyProtoListener.
func (p *proxyProtoConn) NetConn() net.Conn {
	return p.Conn
}

// RawWriteConn exposes the underlying net.Conn for transparent write unwrapping (unlike *tls.Conn whose NetConn bypasses encryption).
func (p *proxyProtoConn) RawWriteConn() net.Conn {
	return p.Conn
}

// UnwrapTCP exposes the raw *net.TCPConn once any peeked PROXY header leftover bytes are drained,
// enabling Linux kernel `splice(2)` zero-copy even when `proxy_protocol=true`!
func (p *proxyProtoConn) UnwrapTCP() (*net.TCPConn, bool) {
	if err := p.ensureParsed(); err != nil || !p.drained.Load() {
		return nil, false
	}
	return unwrapTCP(p.Conn)
}

func (p *proxyProtoConn) CloseWrite() error {
	if cw, ok := p.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

func (p *proxyProtoConn) CanHalfCloseWrite() bool {
	return canConnHalfCloseWrite(p.Conn)
}

func (p *proxyProtoConn) RemoteAddr() net.Addr {
	_ = p.ensureParsed()
	if p.remoteAddr != nil {
		return p.remoteAddr
	}
	return p.Conn.RemoteAddr()
}

func (p *proxyProtoConn) Read(b []byte) (int, error) {
	if err := p.ensureParsed(); err != nil {
		return 0, err
	}
	if !p.drained.Load() {
		p.readMu.Lock()
		if len(p.leftover) > 0 {
			n := copy(b, p.leftover)
			p.leftover = p.leftover[n:]
			if len(p.leftover) == 0 {
				p.leftover = nil
				p.drained.Store(true)
			}
			p.readMu.Unlock()
			return n, nil
		}
		p.drained.Store(true)
		p.readMu.Unlock()
	}
	return p.Conn.Read(b)
}

func (p *proxyProtoConn) parseHeader() error {
	_ = p.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Restore a bounded 12s handshake deadline (instead of infinite time.Time{}) so post-PROXY
	// TLS/WS/protocol Slowloris stalls always time out cleanly!
	defer func() { _ = p.Conn.SetReadDeadline(time.Now().Add(12 * time.Second)) }()

	var hdr [16]byte
	n, err := io.ReadAtLeast(p.Conn, hdr[:], 6)
	if err != nil {
		if p.requireHdr {
			return errors.New("missing required PROXY protocol header")
		}
		p.leftover = append(p.leftover, hdr[:n]...)
		return nil
	}

	// PROXY protocol v1: "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\n" (max 107 bytes per spec)
	if bytes.HasPrefix(hdr[:n], []byte("PROXY ")) {
		var buf [128]byte
		total := copy(buf[:], hdr[:n])
		for !bytes.Contains(buf[:total], []byte("\r\n")) && total < 108 {
			rn, rerr := p.Conn.Read(buf[total:108])
			total += rn
			if rerr != nil || rn == 0 {
				break
			}
		}
		idx := bytes.Index(buf[:total], []byte("\r\n"))
		if idx > 0 {
			line := string(buf[:idx])
			if idx+2 < total {
				p.leftover = append(p.leftover, buf[idx+2:total]...)
			}
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				if ip := net.ParseIP(parts[2]); ip != nil {
					port, _ := strconv.Atoi(parts[4])
					p.remoteAddr = &net.TCPAddr{IP: ip, Port: port}
				}
			}
			return nil
		}
		if p.requireHdr {
			return errors.New("malformed PROXY protocol v1 header")
		}
		p.leftover = append(p.leftover, buf[:total]...)
		return nil
	}

	// PROXY protocol v2 binary signature (16-byte header + addrlen)
	if n < 16 {
		m, rerr := io.ReadFull(p.Conn, hdr[n:16])
		n += m
		if rerr != nil {
			if p.requireHdr {
				return errors.New("incomplete PROXY protocol v2 header")
			}
			p.leftover = append(p.leftover, hdr[:n]...)
			return nil
		}
	}
	if bytes.Equal(hdr[:12], proxyV2Sig[:]) && (hdr[12]&0xF0) == 0x20 {
		addrLen := int(binary.BigEndian.Uint16(hdr[14:16]))
		if addrLen > 4096 {
			return errors.New("PROXY protocol v2 TLV payload exceeds 4096 bytes")
		}
		if addrLen > 0 {
			readBytes := min(addrLen, 64)
			var addrBuf [64]byte
			if _, err := io.ReadFull(p.Conn, addrBuf[:readBytes]); err != nil {
				return err
			}
			if rem := addrLen - readBytes; rem > 0 {
				if _, err := io.CopyN(io.Discard, p.Conn, int64(rem)); err != nil {
					return err
				}
			}
			fam := hdr[13] >> 4
			if fam == 0x1 && readBytes >= 12 { // AF_INET
				srcIP := make(net.IP, 4)
				copy(srcIP, addrBuf[0:4])
				srcPort := int(binary.BigEndian.Uint16(addrBuf[8:10]))
				p.remoteAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}
			} else if fam == 0x2 && readBytes >= 36 { // AF_INET6
				srcIP := make(net.IP, 16)
				copy(srcIP, addrBuf[0:16])
				srcPort := int(binary.BigEndian.Uint16(addrBuf[32:34]))
				p.remoteAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}
			}
		}
		return nil
	}

	if p.requireHdr {
		return errors.New("connection lacks required PROXY protocol header")
	}
	p.leftover = append(p.leftover, hdr[:n]...)
	return nil
}
