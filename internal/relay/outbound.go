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

func validateTargetHost(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("invalid outbound target host length")
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c <= 0x20 || c >= 0x7f || c == '/' || c == '\\' || c == '@' {
			return errors.New("invalid character in outbound target host")
		}
	}
	return nil
}

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
	if err := validateTargetHost(targetHost); err != nil {
		return nil, err
	}
	if route.Action == acl.ActionBlock {
		return nil, errors.New("blocked by ACL/audit rule")
	}
	if route.ForbidPrivate {
		if ip, err := netip.ParseAddr(targetHost); err == nil && acl.IsReservedOrPrivateIP(ip) {
			return nil, errors.New("private/reserved IP blocked by policy")
		}
	}

	if route.Action == acl.ActionDirect && len(route.Outbounds) == 0 {
		return dialDirectWithDNSAndRoute(ctx, targetHost, targetPort, acl.OutboundNode{Type: "direct"}, route, resolver, timeout)
	}

	var lastErr error
	for _, out := range route.Outbounds {
		c, err := dialSingleOutbound(ctx, targetHost, targetPort, out, route, resolver, timeout)
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return dialDirectWithDNSAndRoute(ctx, targetHost, targetPort, acl.OutboundNode{Type: "direct"}, route, resolver, timeout)
}

func dialSingleOutbound(
	ctx context.Context,
	targetHost string,
	targetPort uint16,
	out acl.OutboundNode,
	route acl.OutboundTarget,
	resolver *dns.Resolver,
	timeout time.Duration,
) (net.Conn, error) {
	switch strings.ToLower(out.Type) {
	case "block":
		return nil, errors.New("blocked by route outbound")
	case "direct", "":
		return dialDirectWithDNSAndRoute(ctx, targetHost, targetPort, out, route, resolver, timeout)
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
	return dialDirectWithDNSAndRoute(ctx, host, port, out, acl.OutboundTarget{}, resolver, timeout)
}

func dialDirectWithDNSAndRoute(
	ctx context.Context,
	host string,
	port uint16,
	out acl.OutboundNode,
	route acl.OutboundTarget,
	resolver *dns.Resolver,
	timeout time.Duration,
) (net.Conn, error) {
	hasStrat := out.ListenStrategy != ""
	strat := dns.ParseStrategy(out.ListenStrategy)

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.ResolveAll(dialCtx, host, strat, hasStrat)
	if err != nil {
		return nil, err
	}

	tryDialCandidates := func(cands []netip.Addr) (net.Conn, error) {
		var lastDialErr error
		limit := min(len(cands), 3)
		for i := 0; i < limit; i++ {
			ip := cands[i].Unmap()
			if !route.AllowResolvedIP(ip) {
				lastDialErr = errors.New("resolved IP blocked by ACL/private-IP policy")
				continue
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
			c, derr := d.DialContext(dialCtx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			if derr == nil {
				return c, nil
			}
			lastDialErr = derr
		}
		if lastDialErr == nil {
			lastDialErr = errors.New("no dialable IP candidate")
		}
		return nil, lastDialErr
	}

	c, dialErr := tryDialCandidates(ips)
	if dialErr == nil {
		return c, nil
	}
	// Dual-stack graceful fallback: if ipv6_first resolved only AAAA and the host lacks IPv6 routing, fall back to A!
	if strat == dns.StrategyIPv6First && len(ips) > 0 && ips[0].Is6() {
		if v4s, v4err := resolver.ResolveAll(dialCtx, host, dns.StrategyIPv4Only, true); v4err == nil && len(v4s) > 0 {
			if c4, err4 := tryDialCandidates(v4s); err4 == nil {
				return c4, nil
			}
		}
	}
	return nil, dialErr
}

// ResolveUDPTarget resolves a UDP target host through our custom DNS unlock engine.
func ResolveUDPTarget(ctx context.Context, host string, port uint16, resolver *dns.Resolver) (*net.UDPAddr, error) {
	return ResolveUDPTargetForRoute(ctx, host, port, acl.OutboundTarget{}, resolver)
}

// ResolveUDPTargetForRoute resolves a UDP target host honoring any per-route IPv4/IPv6 strategy and ACL/private-IP rules.
func ResolveUDPTargetForRoute(ctx context.Context, host string, port uint16, route acl.OutboundTarget, resolver *dns.Resolver) (*net.UDPAddr, error) {
	if err := validateTargetHost(host); err != nil {
		return nil, err
	}
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
	if !route.AllowResolvedIP(ip) {
		return nil, errors.New("resolved UDP IP blocked by ACL/private-IP policy")
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
		if len(out.Username) > 255 || len(out.Password) > 255 {
			c.Close()
			return nil, errors.New("socks5 credentials exceed 255 bytes")
		}
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

func readBoundedHTTPHeaderLine(br *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		frag, isPrefix, err := br.ReadLine()
		if err != nil {
			return "", err
		}
		if len(buf)+len(frag) > maxLen {
			return "", errors.New("proxy HTTP response header too long")
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
	br := bufio.NewReaderSize(c, 2048)
	status, err := readBoundedHTTPHeaderLine(br, 4096)
	if err != nil || (!strings.HasPrefix(status, "HTTP/1.1 200") && !strings.HasPrefix(status, "HTTP/1.0 200")) {
		c.Close()
		return nil, errors.New("http connect proxy failed")
	}
	for hdrCnt := 0; ; hdrCnt++ {
		if hdrCnt >= 64 {
			c.Close()
			return nil, errors.New("too many http connect response headers")
		}
		line, err := readBoundedHTTPHeaderLine(br, 4096)
		if err != nil {
			c.Close()
			return nil, err
		}
		if line == "" {
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

func (v *vlessClientConn) CanHalfCloseWrite() bool {
	return canConnHalfCloseWrite(v.Conn)
}

func (v *vlessClientConn) CloseWrite() error {
	if cw, ok := v.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("half-close unsupported")
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

func (s *ssClientConn) flushTargetHeaderIfNeeded() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if len(s.pendingHdr) == 0 {
		return nil
	}
	hdr := s.pendingHdr
	s.pendingHdr = nil

	prefixSalt := make([]byte, s.keyLen)
	if _, err := rand.Read(prefixSalt); err != nil {
		return err
	}
	aead, err := s.makeSubAEAD(prefixSalt)
	if err != nil {
		return err
	}
	s.writeAEAD = aead

	bp := bufpool.Get(len(prefixSalt) + 2 + 16 + len(hdr) + 16)
	out := (*bp)[:0]
	out = append(out, prefixSalt...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(hdr)))
	out = s.writeAEAD.Seal(out, s.writeNonce[:], lb[:], nil)
	incSSNonce(&s.writeNonce)
	out = s.writeAEAD.Seal(out, s.writeNonce[:], hdr, nil)
	incSSNonce(&s.writeNonce)

	_, werr := s.Conn.Write(out)
	bufpool.Put(bp)
	return werr
}

func (s *ssClientConn) Read(p []byte) (int, error) {
	// Ensure target address header has been transmitted even on server-speaks-first protocols (SSH/SMTP/MySQL)!
	if err := s.flushTargetHeaderIfNeeded(); err != nil {
		return 0, err
	}
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
	status, err := readBoundedHTTPHeaderLine(br, 4096)
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101") {
		return nil, errors.New("outbound websocket upgrade failed")
	}
	for hdrCnt := 0; ; hdrCnt++ {
		if hdrCnt >= 64 {
			return nil, errors.New("too many outbound websocket headers")
		}
		line, err := readBoundedHTTPHeaderLine(br, 4096)
		if err != nil {
			return nil, err
		}
		if line == "" {
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
			if plen < 0 || plen > 16*1024*1024 {
				return 0, errors.New("outbound websocket frame too large")
			}
		}
		if op >= 0x8 && plen > 125 {
			return 0, errors.New("outbound websocket control frame exceeds 125 bytes")
		}
		if op == 0x8 {
			return 0, io.EOF
		}
		if op == 0x9 { // Ping -> reply masked Pong so upstream CDN/WS server never drops idle tunnel
			var ping [125]byte
			if _, err := io.ReadFull(w.br, ping[:plen]); err != nil {
				return 0, err
			}
			_ = w.writeClientFrame(0xA, ping[:plen])
			continue
		}
		if op == 0x1 || op == 0x2 || op == 0x0 {
			w.frameRem = plen
		} else if plen > 0 {
			if _, err := io.CopyN(io.Discard, w.br, plen); err != nil {
				return 0, err
			}
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
	if err := w.writeClientFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsClientConn) writeClientFrame(opcode byte, p []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	var mkey [4]byte
	_, _ = rand.Read(mkey[:])

	bp := bufpool.Get(max(len(p), 1))
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
	hdr[0] = 0x80 | (opcode & 0x0F)
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
	_, err := bufs.WriteTo(w.Conn)
	return err
}

// DialUDPForRoute opens a PacketConn honoring SOCKS5 `UDP ASSOCIATE` when `route` targets a SOCKS5 outbound
// (e.g. WARP wireproxy `127.0.0.1:40000`), falling back cleanly to a local bound UDP socket if unsupported.
func DialUDPForRoute(ctx context.Context, route acl.OutboundTarget, preferIPv6 bool, resolver *dns.Resolver) (net.PacketConn, error) {
	for _, out := range route.Outbounds {
		t := strings.ToLower(out.Type)
		if t == "socks5" || t == "socks" {
			if pc, err := dialSOCKS5UDPAssociate(ctx, out, resolver, 5*time.Second); err == nil {
				return pc, nil
			}
		}
	}
	localBind := ""
	if lu := LocalUDPAddrForRoute(route, preferIPv6); lu != nil {
		localBind = net.JoinHostPort(lu.IP.String(), "0")
	}
	return net.ListenPacket("udp", localBind)
}

type socks5UDPPacketConn struct {
	net.PacketConn
	ctrlConn  net.Conn
	relayAddr *net.UDPAddr
}

func dialSOCKS5UDPAssociate(ctx context.Context, out acl.OutboundNode, resolver *dns.Resolver, timeout time.Duration) (net.PacketConn, error) {
	c, err := dialProxyTransport(ctx, out, resolver, timeout)
	if err != nil {
		return nil, err
	}
	if out.Username != "" {
		if len(out.Username) > 255 || len(out.Password) > 255 {
			c.Close()
			return nil, errors.New("socks5 credentials too long")
		}
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
		return nil, errors.New("socks5 udp greeting failed")
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
			return nil, errors.New("socks5 udp auth rejected")
		}
	} else if resp[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 udp unsupported auth")
	}

	// Send CMD = 0x03 (UDP ASSOCIATE) with 0.0.0.0:0
	if _, err := c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		c.Close()
		return nil, err
	}
	var rhead [4]byte
	if _, err := io.ReadFull(c, rhead[:]); err != nil || rhead[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5 udp associate rejected")
	}
	var bndIP net.IP
	var bndPort int
	switch rhead[3] {
	case 0x01:
		var b [6]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			c.Close()
			return nil, err
		}
		bndIP = net.IP(b[0:4])
		bndPort = int(binary.BigEndian.Uint16(b[4:6]))
	case 0x04:
		var b [18]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			c.Close()
			return nil, err
		}
		bndIP = net.IP(b[0:16])
		bndPort = int(binary.BigEndian.Uint16(b[16:18]))
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			c.Close()
			return nil, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(c, b); err != nil {
			c.Close()
			return nil, err
		}
		bndPort = int(binary.BigEndian.Uint16(b[l[0]:]))
	default:
		c.Close()
		return nil, errors.New("socks5 udp unknown atyp")
	}
	if bndPort <= 0 {
		c.Close()
		return nil, errors.New("socks5 udp invalid relay port")
	}
	if len(bndIP) == 0 || bndIP.IsUnspecified() {
		if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			bndIP = ta.IP
		}
	}
	_ = c.SetDeadline(time.Time{})

	bindNet := "udp4"
	localBind := "0.0.0.0:0"
	if bndIP.To4() == nil {
		bindNet = "udp6"
		localBind = "[::]:0"
	}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok && ta.IP.IsLoopback() {
		if bndIP.To4() != nil {
			localBind = "127.0.0.1:0"
		} else {
			localBind = "[::1]:0"
		}
	}
	pc, err := net.ListenPacket(bindNet, localBind)
	if err != nil {
		c.Close()
		return nil, err
	}
	spc := &socks5UDPPacketConn{
		PacketConn: pc,
		ctrlConn:   c,
		relayAddr:  &net.UDPAddr{IP: bndIP, Port: bndPort},
	}
	// Close UDP socket automatically if SOCKS5 TCP control stream drops
	go func() {
		var one [1]byte
		_, _ = c.Read(one[:])
		_ = pc.Close()
	}()
	return spc, nil
}

func (s *socks5UDPPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("socks5 udp expects *net.UDPAddr")
	}
	bp := bufpool.Get(24 + len(p))
	defer bufpool.Put(bp)
	pkt := (*bp)[:0]
	pkt = append(pkt, 0x00, 0x00, 0x00) // RSV(2), FRAG=0
	if ip4 := ua.IP.To4(); ip4 != nil {
		pkt = append(pkt, 0x01)
		pkt = append(pkt, ip4...)
	} else {
		pkt = append(pkt, 0x04)
		pkt = append(pkt, ua.IP.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(ua.Port))
	pkt = append(pkt, pb[:]...)
	pkt = append(pkt, p...)
	if _, err := s.PacketConn.WriteTo(pkt, s.relayAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *socks5UDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bp := bufpool.Get(bufpool.MaxUDPSize)
	raw := *bp
	defer bufpool.Put(bp)
	for {
		n, _, err := s.PacketConn.ReadFrom(raw)
		if err != nil {
			return 0, nil, err
		}
		if n < 10 || raw[2] != 0x00 { // ignore fragmented or malformed SOCKS5 UDP packets
			continue
		}
		pos := 4
		var srcIP net.IP
		switch raw[3] {
		case 0x01:
			if n < pos+6 {
				continue
			}
			srcIP = make(net.IP, 4)
			copy(srcIP, raw[pos:pos+4])
			pos += 4
		case 0x04:
			if n < pos+18 {
				continue
			}
			srcIP = make(net.IP, 16)
			copy(srcIP, raw[pos:pos+16])
			pos += 16
		case 0x03:
			dlen := int(raw[pos])
			pos++
			if n < pos+dlen+2 {
				continue
			}
			srcIP = net.ParseIP(string(raw[pos : pos+dlen]))
			pos += dlen
		default:
			continue
		}
		srcPort := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		copied := copy(p, raw[pos:n])
		return copied, &net.UDPAddr{IP: srcIP, Port: srcPort}, nil
	}
}

func (s *socks5UDPPacketConn) Close() error {
	_ = s.ctrlConn.Close()
	return s.PacketConn.Close()
}
