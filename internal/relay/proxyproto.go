package relay

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var proxyV2Sig = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ProxyProtoListener wraps a net.Listener and transparently parses HAProxy PROXY Protocol v1 & v2
// headers (`proxy_protocol=true` in soga.conf) so transit/relay nodes preserve real client IPs.
type ProxyProtoListener struct {
	net.Listener
}

func (l *ProxyProtoListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &proxyProtoConn{Conn: c}, nil
}

type proxyProtoConn struct {
	net.Conn
	parsed     bool
	remoteAddr net.Addr
	leftover   []byte
}

func (p *proxyProtoConn) RemoteAddr() net.Addr {
	if !p.parsed {
		_ = p.parseHeader()
	}
	if p.remoteAddr != nil {
		return p.remoteAddr
	}
	return p.Conn.RemoteAddr()
}

func (p *proxyProtoConn) Read(b []byte) (int, error) {
	if !p.parsed {
		if err := p.parseHeader(); err != nil {
			return 0, err
		}
	}
	if len(p.leftover) > 0 {
		n := copy(b, p.leftover)
		p.leftover = p.leftover[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *proxyProtoConn) parseHeader() error {
	p.parsed = true
	_ = p.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = p.Conn.SetReadDeadline(time.Time{}) }()

	var hdr [16]byte
	n, err := io.ReadAtLeast(p.Conn, hdr[:], 6)
	if err != nil {
		p.leftover = append(p.leftover, hdr[:n]...)
		return nil
	}

	// PROXY protocol v1: "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\n"
	if bytes.HasPrefix(hdr[:n], []byte("PROXY ")) {
		buf := make([]byte, 0, 108)
		buf = append(buf, hdr[:n]...)
		for !bytes.Contains(buf, []byte("\r\n")) && len(buf) < 108 {
			var one [1]byte
			if _, rerr := p.Conn.Read(one[:]); rerr != nil {
				break
			}
			buf = append(buf, one[0])
		}
		idx := bytes.Index(buf, []byte("\r\n"))
		if idx > 0 {
			line := string(buf[:idx])
			p.leftover = append(p.leftover, buf[idx+2:]...)
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				if ip := net.ParseIP(parts[2]); ip != nil {
					port, _ := strconv.Atoi(parts[4])
					p.remoteAddr = &net.TCPAddr{IP: ip, Port: port}
				}
			}
			return nil
		}
		p.leftover = append(p.leftover, buf...)
		return nil
	}

	// PROXY protocol v2 binary signature (16-byte header + addrlen)
	if n < 16 {
		m, rerr := io.ReadFull(p.Conn, hdr[n:16])
		n += m
		if rerr != nil {
			p.leftover = append(p.leftover, hdr[:n]...)
			return nil
		}
	}
	if bytes.Equal(hdr[:12], proxyV2Sig[:]) && (hdr[12]&0xF0) == 0x20 {
		addrLen := int(binary.BigEndian.Uint16(hdr[14:16]))
		if addrLen > 0 && addrLen <= 512 {
			addrBuf := make([]byte, addrLen)
			if _, err := io.ReadFull(p.Conn, addrBuf); err != nil {
				return err
			}
			fam := hdr[13] >> 4
			if fam == 0x1 && addrLen >= 12 { // AF_INET
				srcIP := net.IP(addrBuf[0:4])
				srcPort := int(binary.BigEndian.Uint16(addrBuf[8:10]))
				p.remoteAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}
			} else if fam == 0x2 && addrLen >= 36 { // AF_INET6
				srcIP := net.IP(addrBuf[0:16])
				srcPort := int(binary.BigEndian.Uint16(addrBuf[32:34]))
				p.remoteAddr = &net.TCPAddr{IP: srcIP, Port: srcPort}
			}
		}
		return nil
	}

	p.leftover = append(p.leftover, hdr[:n]...)
	return nil
}
