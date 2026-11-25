package relay

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/dns"
)

// DialOutbound connects to targetHost:targetPort directly (resolving via custom `dns.Resolver`
// and honoring IPv4/IPv6 strategy & local source IP binding) or via `routes.toml` outbound proxies
// (`socks5`, `http`/`https`, `ss`, `trojan`, `vless`) with automatic failover across `route.Outbounds`.
func DialOutbound(
	ctx context.Context,
	targetHost string,
	targetPort uint16,
	route acl.OutboundTarget,
	resolver *dns.Resolver,
	timeout time.Duration,
) (net.Conn, error) {
	if route.Action == acl.ActionBlock {
		return nil, errors.New("blocked by ACL/audit rule")
	}

	if route.Action == acl.ActionDirect && len(route.Outbounds) == 0 {
		return dialDirectWithDNS(ctx, targetHost, targetPort, acl.OutboundNode{Type: "direct"}, resolver, timeout)
	}

	var lastErr error
	for _, out := range route.Outbounds {
		c, err := dialSingleOutbound(ctx, targetHost, targetPort, out, resolver, timeout)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return dialDirectWithDNS(ctx, targetHost, targetPort, acl.OutboundNode{Type: "direct"}, resolver, timeout)
}

func dialSingleOutbound(
	ctx context.Context,
	targetHost string,
	targetPort uint16,
	out acl.OutboundNode,
	resolver *dns.Resolver,
	timeout time.Duration,
) (net.Conn, error) {
	switch strings.ToLower(out.Type) {
	case "block":
		return nil, errors.New("blocked by route outbound")
	case "direct", "":
		return dialDirectWithDNS(ctx, targetHost, targetPort, out, resolver, timeout)
	case "socks5", "socks":
		return dialNodeSOCKS5(ctx, out, targetHost, targetPort, resolver, timeout)
	case "http", "https":
		return dialNodeHTTPConnect(ctx, out, targetHost, targetPort, resolver, timeout)
	case "ss", "shadowsocks":
		return dialNodeShadowsocks(ctx, out, targetHost, targetPort, resolver, timeout)
	case "trojan":
		return dialNodeTrojan(ctx, out, targetHost, targetPort, resolver, timeout)
	case "vless":
		return dialNodeVLESS(ctx, out, targetHost, targetPort, resolver, timeout)
	default:
		return nil, fmt.Errorf("unsupported outbound type %q", out.Type)
	}
}

func dialDirectWithDNS(
	ctx context.Context,
	host string,
	port uint16,
	out acl.OutboundNode,
	resolver *dns.Resolver,
	timeout time.Duration,
) (net.Conn, error) {
	hasStrat := out.ListenStrategy != ""
	strat := dns.ParseStrategy(out.ListenStrategy)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ip, err := resolver.Resolve(dialCtx, host, strat, hasStrat)
	if err != nil {
		return nil, err
	}

	d := net.Dialer{
		Timeout:   timeout,
		KeepAlive: 45 * time.Second,
	}
	if ip.Is4() && out.ListenIPv4 != "" {
		if lip := net.ParseIP(out.ListenIPv4); lip != nil {
			d.LocalAddr = &net.TCPAddr{IP: lip}
		}
	} else if ip.Is6() && out.ListenIPv6 != "" {
		if lip := net.ParseIP(out.ListenIPv6); lip != nil {
			d.LocalAddr = &net.TCPAddr{IP: lip}
		}
	}

	network := "tcp4"
	if ip.Is6() {
		network = "tcp6"
	}
	return d.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
}

// ResolveUDPTarget resolves a UDP target host through our custom DNS unlock engine.
func ResolveUDPTarget(ctx context.Context, host string, port uint16, resolver *dns.Resolver) (*net.UDPAddr, error) {
	return ResolveUDPTargetForRoute(ctx, host, port, acl.OutboundTarget{}, resolver)
}

// ResolveUDPTargetForRoute resolves a UDP target host honoring any per-route IPv4/IPv6 strategy.
func ResolveUDPTargetForRoute(ctx context.Context, host string, port uint16, route acl.OutboundTarget, resolver *dns.Resolver) (*net.UDPAddr, error) {
	strat := dns.StrategyIPv4First
	hasStrat := false
	if len(route.Outbounds) > 0 && route.Outbounds[0].ListenStrategy != "" {
		strat = dns.ParseStrategy(route.Outbounds[0].ListenStrategy)
		hasStrat = true
	}
	ip, err := resolver.Resolve(ctx, host, strat, hasStrat)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(port)}, nil
}

// LocalUDPAddrForRoute returns the bound local *net.UDPAddr when a route specifies `listen = "10.163.0.x"` / `listen_ipv4` / `listen_ipv6`.
func LocalUDPAddrForRoute(route acl.OutboundTarget, preferIPv6 bool) *net.UDPAddr {
	if len(route.Outbounds) == 0 {
		return nil
	}
	out := route.Outbounds[0]
	if preferIPv6 && out.ListenIPv6 != "" {
		if ip := net.ParseIP(out.ListenIPv6); ip != nil {
			return &net.UDPAddr{IP: ip}
		}
	}
	if !preferIPv6 && out.ListenIPv4 != "" {
		if ip := net.ParseIP(out.ListenIPv4); ip != nil {
			return &net.UDPAddr{IP: ip}
		}
	}
	return nil
}

func dialProxyTransport(ctx context.Context, out acl.OutboundNode, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	if out.Server == "" || out.Port <= 0 {
		return nil, errors.New("outbound proxy server/port missing")
	}
	rawConn, err := dialDirectWithDNS(ctx, out.Server, uint16(out.Port), acl.OutboundNode{
		Type:           "direct",
		ListenIPv4:     out.ListenIPv4,
		ListenIPv6:     out.ListenIPv6,
		ListenStrategy: out.ListenStrategy,
	}, resolver, timeout)
	if err != nil {
		return nil, err
	}
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	conn := rawConn
	if out.TLS || out.Type == "trojan" || out.Type == "https" {
		sni := out.SNI
		if sni == "" {
			sni = out.Server
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: out.SkipCertVerify,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	if out.Network == "ws" {
		wsConn, err := clientWSHandshake(conn, out)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = wsConn
	}
	return conn, nil
}

func dialNodeSOCKS5(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	if out.Username != "" {
		_, err = c.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		_, err = c.Write([]byte{0x05, 0x01, 0x00})
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	var resp [2]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil || resp[0] != 0x05 {
		c.Close()
		return nil, errors.New("socks5 greeting failed")
	}
	if resp[1] == 0x02 {
		auth := make([]byte, 0, 3+len(out.Username)+len(out.Password))
		auth = append(auth, 0x01, byte(len(out.Username)))
		auth = append(auth, out.Username...)
		auth = append(auth, byte(len(out.Password)))
		auth = append(auth, out.Password...)
		if _, err := c.Write(auth); err != nil {
			c.Close()
			return nil, err
		}
		if _, err := io.ReadFull(c, resp[:]); err != nil || resp[1] != 0x00 {
			c.Close()
			return nil, errors.New("socks5 auth rejected")
		}
	} else if resp[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 unsupported auth method")
	}

	req := appendSOCKS5Target(append([]byte(nil), 0x05, 0x01, 0x00), targetHost, targetPort)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}

	var rhead [4]byte
	if _, err := io.ReadFull(c, rhead[:]); err != nil || rhead[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 connect rejected")
	}
	skip := 0
	switch rhead[3] {
	case 0x01:
		skip = 6
	case 0x04:
		skip = 18
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	}
	if skip > 0 {
		var discard [260]byte
		if _, err := io.ReadFull(c, discard[:skip]); err != nil {
			c.Close()
			return nil, err
		}
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func dialNodeHTTPConnect(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	var sb strings.Builder
	sb.WriteString("CONNECT ")
	sb.WriteString(targetAddr)
	sb.WriteString(" HTTP/1.1\r\nHost: ")
	sb.WriteString(targetAddr)
	sb.WriteString("\r\n")
	if out.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(out.Username + ":" + out.Password))
		sb.WriteString("Proxy-Authorization: Basic ")
		sb.WriteString(cred)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	if _, err := c.Write([]byte(sb.String())); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200") {
		c.Close()
		return nil, errors.New("http connect proxy failed")
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &PrependConn{Conn: c, Reader: br}, nil
	}
	return c, nil
}

func dialNodeTrojan(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	out.TLS = true
	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum224([]byte(out.Password))
	var hdr []byte
	hdr = append(hdr, hex.EncodeToString(sum[:])...)
	hdr = append(hdr, '\r', '\n', 0x01)
	hdr = appendSOCKS5Target(hdr, targetHost, targetPort)
	hdr = append(hdr, '\r', '\n')

	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func dialNodeVLESS(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	uuidBytes, err := parseCleanUUID(out.UUID)
	if err != nil {
		return nil, err
	}
	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, 32+len(targetHost))
	hdr = append(hdr, 0x00) // VLESS v0
	hdr = append(hdr, uuidBytes[:]...)
	hdr = append(hdr, 0x00) // addon len 0
	hdr = append(hdr, 0x01) // TCP
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], targetPort)
	hdr = append(hdr, pb[:]...)
	if ip, ierr := netip.ParseAddr(targetHost); ierr == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a4 := ip.As4()
			hdr = append(hdr, 0x01)
			hdr = append(hdr, a4[:]...)
		} else {
			a16 := ip.As16()
			hdr = append(hdr, 0x03)
			hdr = append(hdr, a16[:]...)
		}
	} else {
		hdr = append(hdr, 0x02, byte(len(targetHost)))
		hdr = append(hdr, targetHost...)
	}

	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return &vlessClientConn{Conn: c}, nil
}

type vlessClientConn struct {
	net.Conn
	readMu  sync.Mutex
	readHdr bool
}

func (v *vlessClientConn) Read(p []byte) (int, error) {
	v.readMu.Lock()
	if !v.readHdr {
		v.readHdr = true
		var rh [2]byte
		if _, err := io.ReadFull(v.Conn, rh[:]); err != nil {
			v.readMu.Unlock()
			return 0, err
		}
		if rh[1] > 0 {
			var addon [256]byte
			if _, err := io.ReadFull(v.Conn, addon[:rh[1]]); err != nil {
				v.readMu.Unlock()
				return 0, err
			}
		}
	}
	v.readMu.Unlock()
	return v.Conn.Read(p)
}

func dialNodeShadowsocks(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	keyLen := 32
	isChaCha := false
	switch strings.ToLower(out.Cipher) {
	case "aes-128-gcm":
		keyLen = 16
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		isChaCha = true
	}

	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})

	masterKey := deriveEVPKey(out.Password, keyLen)
	targetHdr := appendSOCKS5Target(nil, targetHost, targetPort)
	return &ssClientConn{
		Conn:       c,
		keyLen:     keyLen,
		isChaCha:   isChaCha,
		masterKey:  masterKey,
		pendingHdr: targetHdr,
	}, nil
}

type ssClientConn struct {
	net.Conn
	keyLen     int
	isChaCha   bool
	masterKey  []byte
	pendingHdr []byte

	writeMu    sync.Mutex
	writeAEAD  cipher.AEAD
	writeNonce [12]byte

	readMu    sync.Mutex
	readAEAD  cipher.AEAD
	readNonce [12]byte
	leftover  []byte
}

func (s *ssClientConn) makeSubAEAD(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, s.keyLen)
	r := hkdf.New(sha1.New, s.masterKey, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(r, subkey); err != nil {
		return nil, err
	}
	if s.isChaCha {
		return chacha20poly1305.New(subkey)
	}
	blk, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (s *ssClientConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	origLen := len(p)
	var combined []byte
	if len(s.pendingHdr) > 0 {
		combined = make([]byte, 0, len(s.pendingHdr)+len(p))
		combined = append(combined, s.pendingHdr...)
		combined = append(combined, p...)
		s.pendingHdr = nil
		p = combined
	}

	var prefixSalt []byte
	if s.writeAEAD == nil {
		prefixSalt = make([]byte, s.keyLen)
		if _, err := rand.Read(prefixSalt); err != nil {
			return 0, err
		}
		aead, err := s.makeSubAEAD(prefixSalt)
		if err != nil {
			return 0, err
		}
		s.writeAEAD = aead
	}

	for len(p) > 0 {
		chunk := p
		if len(chunk) > 0x3FFF {
			chunk = p[:0x3FFF]
		}
		p = p[len(chunk):]

		bp := bufpool.Get(len(prefixSalt) + 2 + 16 + len(chunk) + 16)
		out := (*bp)[:0]
		if len(prefixSalt) > 0 {
			out = append(out, prefixSalt...)
			prefixSalt = nil
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(chunk)))
		out = s.writeAEAD.Seal(out, s.writeNonce[:], lb[:], nil)
		incSSNonce(&s.writeNonce)
		out = s.writeAEAD.Seal(out, s.writeNonce[:], chunk, nil)
		incSSNonce(&s.writeNonce)

		_, err := s.Conn.Write(out)
		bufpool.Put(bp)
		if err != nil {
			return 0, err
		}
	}
	return origLen, nil
}

func (s *ssClientConn) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}
	if s.readAEAD == nil {
		salt := make([]byte, s.keyLen)
		if _, err := io.ReadFull(s.Conn, salt); err != nil {
			return 0, err
		}
		aead, err := s.makeSubAEAD(salt)
		if err != nil {
			return 0, err
		}
		s.readAEAD = aead
	}

	var lenEnc [18]byte
	if _, err := io.ReadFull(s.Conn, lenEnc[:]); err != nil {
		return 0, err
	}
	var lb [2]byte
	if _, err := s.readAEAD.Open(lb[:0], s.readNonce[:], lenEnc[:], nil); err != nil {
		return 0, err
	}
	incSSNonce(&s.readNonce)
	cLen := int(binary.BigEndian.Uint16(lb[:]) & 0x3FFF)
	if cLen == 0 {
		return 0, io.EOF
	}

	bp := bufpool.Get(cLen + 16)
	defer bufpool.Put(bp)
	enc := (*bp)[:cLen+16]
	if _, err := io.ReadFull(s.Conn, enc); err != nil {
		return 0, err
	}
	plain, err := s.readAEAD.Open(enc[:0], s.readNonce[:], enc, nil)
	if err != nil {
		return 0, err
	}
	incSSNonce(&s.readNonce)

	n := copy(p, plain)
	if n < len(plain) {
		s.leftover = append(s.leftover[:0], plain[n:]...)
	}
	return n, nil
}

func incSSNonce(n *[12]byte) {
	for i := 0; i < 12; i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func deriveEVPKey(password string, keyLen int) []byte {
	var b, prev []byte
	pw := []byte(password)
	for len(b) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write(pw)
		prev = h.Sum(nil)
		b = append(b, prev...)
	}
	out := make([]byte, keyLen)
	copy(out, b[:keyLen])
	return out
}

func appendSOCKS5Target(dst []byte, host string, port uint16) []byte {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a4 := ip.As4()
			dst = append(dst, 0x01)
			dst = append(dst, a4[:]...)
		} else {
			a16 := ip.As16()
			dst = append(dst, 0x04)
			dst = append(dst, a16[:]...)
		}
	} else {
		dst = append(dst, 0x03, byte(len(host)))
		dst = append(dst, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	return append(dst, pb[:]...)
}

func parseCleanUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, errors.New("invalid vless outbound uuid")
	}
	_, err := hex.Decode(out[:], []byte(clean))
	return out, err
}

// clientWSHandshake performs a minimal RFC 6455 WebSocket client handshake for WS outbounds.
func clientWSHandshake(c net.Conn, out acl.OutboundNode) (net.Conn, error) {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	wsKey := base64.StdEncoding.EncodeToString(nonce[:])

	path := out.WSPath
	if path == "" {
		path = "/"
	}
	host := out.SNI
	if host == "" {
		host = out.Server
	}

	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + wsKey + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 1024)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 101 ") {
		return nil, errors.New("outbound websocket upgrade failed")
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return &wsClientConn{Conn: c, br: br}, nil
}

type wsClientConn struct {
	net.Conn
	br       *bufio.Reader
	readMu   sync.Mutex
	frameRem int64
	writeMu  sync.Mutex
}

func (w *wsClientConn) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	for w.frameRem == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			return 0, err
		}
		op := hdr[0] & 0x0F
		plen := int64(hdr[1] & 0x7F)
		if plen == 126 {
			var e [2]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return 0, err
			}
			plen = int64(binary.BigEndian.Uint16(e[:]))
		} else if plen == 127 {
			var e [8]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return 0, err
			}
			plen = int64(binary.BigEndian.Uint64(e[:]))
		}
		if op == 0x8 {
			return 0, io.EOF
		}
		if op == 0x1 || op == 0x2 || op == 0x0 {
			w.frameRem = plen
		} else if plen > 0 {
			_, _ = io.CopyN(io.Discard, w.br, plen)
		}
	}
	toRead := int64(len(p))
	if toRead > w.frameRem {
		toRead = w.frameRem
	}
	n, err := w.br.Read(p[:toRead])
	w.frameRem -= int64(n)
	return n, err
}

func (w *wsClientConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	var mkey [4]byte
	_, _ = rand.Read(mkey[:])

	bp := bufpool.Get(len(p))
	defer bufpool.Put(bp)
	masked := (*bp)[:len(p)]
	copy(masked, p)

	m32 := binary.LittleEndian.Uint32(mkey[:])
	m64 := uint64(m32)<<32 | uint64(m32)
	i := 0
	for ; i+8 <= len(masked); i += 8 {
		v := binary.LittleEndian.Uint64(masked[i : i+8])
		binary.LittleEndian.PutUint64(masked[i:i+8], v^m64)
	}
	for ; i < len(masked); i++ {
		masked[i] ^= mkey[i&3]
	}

	var hdr [14]byte
	hdr[0] = 0x82
	hlen := 2
	n := len(masked)
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
	case n <= 65535:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		hlen = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		hlen = 10
	}
	copy(hdr[hlen:hlen+4], mkey[:])
	bufs := net.Buffers{hdr[:hlen+4], masked}
	if _, err := bufs.WriteTo(w.Conn); err != nil {
		return 0, err
	}
	return len(p), nil
}
