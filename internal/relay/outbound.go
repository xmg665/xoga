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
	if !hasStrat {
		if out.ListenIPv4 != "" && out.ListenIPv6 == "" {
			strat = dns.StrategyIPv4Only
			hasStrat = true
		} else if out.ListenIPv6 != "" && out.ListenIPv4 == "" {
			strat = dns.StrategyIPv6Only
			hasStrat = true
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.ResolveAll(dialCtx, host, strat, hasStrat)
	if err != nil {
		return nil, err
	}

	tryDialCandidates := func(attemptCtx context.Context, cands []netip.Addr, budget time.Duration) (net.Conn, error) {
		var lastDialErr error
		limit := min(len(cands), 3)
		perAttempt := budget
		if limit > 1 && budget > 4*time.Second {
			// Cap each attempt when multiple candidates exist so one blackholed IP
			// doesn't exhaust the entire dial budget before trying the next candidate.
			perAttempt = max(budget/2, 4*time.Second)
		}
		for i := 0; i < limit; i++ {
			ip := cands[i].Unmap()
			if !route.AllowResolvedIP(ip) {
				lastDialErr = errors.New("resolved IP blocked by ACL/private-IP policy")
				continue
			}
			d := net.Dialer{
				Timeout:   perAttempt,
				KeepAlive: 45 * time.Second,
			}
			if ip.Is4() {
				if out.ListenIPv4 != "" {
					lip := net.ParseIP(strings.Trim(out.ListenIPv4, "[]"))
					if lip == nil || lip.To4() == nil {
						lastDialErr = fmt.Errorf("invalid outbound listen_ipv4 %q", out.ListenIPv4)
						continue
					}
					d.LocalAddr = &net.TCPAddr{IP: lip}
				} else if out.ListenIPv6 != "" {
					// IPv6-only bound route must never leak host default IPv4.
					lastDialErr = errors.New("outbound route is bound to IPv6 only; refusing unbound IPv4 dial")
					continue
				}
			} else if ip.Is6() {
				if out.ListenIPv6 != "" {
					lip := net.ParseIP(strings.Trim(out.ListenIPv6, "[]"))
					if lip == nil || lip.To4() != nil {
						lastDialErr = fmt.Errorf("invalid outbound listen_ipv6 %q", out.ListenIPv6)
						continue
					}
					d.LocalAddr = &net.TCPAddr{IP: lip}
				} else if out.ListenIPv4 != "" {
					// IPv4-only bound route must never leak host default IPv6.
					lastDialErr = errors.New("outbound route is bound to IPv4 only; refusing unbound IPv6 dial")
					continue
				}
			}
			network := "tcp4"
			if ip.Is6() {
				network = "tcp6"
			}
			c, derr := d.DialContext(attemptCtx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
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

	effStrat := strat
	if !hasStrat {
		effStrat = resolver.DefaultStrategy()
	}
	_, isLiteralIP := netip.ParseAddr(host)
	willFallbackV4 := isLiteralIP != nil && effStrat == dns.StrategyIPv6First && len(ips) > 0 && ips[0].Is6() && !(out.ListenIPv6 != "" && out.ListenIPv4 == "")

	primaryCtx := dialCtx
	primaryBudget := timeout
	var primaryCancel context.CancelFunc
	if willFallbackV4 {
		// Reserve at least half the dial budget (or up to 4s for v6) so blackholed IPv6
		// never exhausts dialCtx before the IPv4 fallback can resolve and connect.
		v6Budget := timeout / 2
		if v6Budget > 4*time.Second {
			v6Budget = 4 * time.Second
		}
		if v6Budget < 500*time.Millisecond {
			v6Budget = timeout / 2
		}
		if v6Budget > 0 && v6Budget < timeout {
			primaryCtx, primaryCancel = context.WithTimeout(dialCtx, v6Budget)
			primaryBudget = v6Budget
		}
	}
	c, dialErr := tryDialCandidates(primaryCtx, ips, primaryBudget)
	if primaryCancel != nil {
		primaryCancel()
	}
	if dialErr == nil {
		return c, nil
	}
	// Dual-stack graceful fallback: if ipv6_first resolved only AAAA and the host lacks IPv6 routing, fall back to A!
	if willFallbackV4 {
		fbCtx := dialCtx
		var fbCancel context.CancelFunc
		if fbCtx.Err() != nil && ctx.Err() == nil {
			fbCtx, fbCancel = context.WithTimeout(ctx, min(timeout, 5*time.Second))
		}
		if fbCancel != nil {
			defer fbCancel()
		}
		if v4s, v4err := resolver.ResolveAll(fbCtx, host, dns.StrategyIPv4Only, true); v4err == nil && len(v4s) > 0 {
			fbBudget := timeout
			if dl, ok := fbCtx.Deadline(); ok {
				if rem := time.Until(dl); rem > 0 && rem < fbBudget {
					fbBudget = rem
				}
			}
			if c4, err4 := tryDialCandidates(fbCtx, v4s, fbBudget); err4 == nil {
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
	var directBind *acl.OutboundNode
	if len(route.Outbounds) > 0 {
		out := &route.Outbounds[0]
		t := strings.ToLower(out.Type)
		if out.ListenStrategy != "" {
			strat = dns.ParseStrategy(out.ListenStrategy)
			hasStrat = true
		}
		if t == "direct" || t == "" {
			directBind = out
			if !hasStrat {
				if out.ListenIPv4 != "" && out.ListenIPv6 == "" {
					strat = dns.StrategyIPv4Only
					hasStrat = true
				} else if out.ListenIPv6 != "" && out.ListenIPv4 == "" {
					strat = dns.StrategyIPv6Only
					hasStrat = true
				}
			}
		}
	}
	ip, err := resolver.Resolve(ctx, host, strat, hasStrat)
	if err != nil {
		return nil, err
	}
	ip = ip.Unmap()
	if !route.AllowResolvedIP(ip) {
		return nil, errors.New("resolved UDP IP blocked by ACL/private-IP policy")
	}
	if directBind != nil {
		if ip.Is6() && directBind.ListenIPv6 == "" && directBind.ListenIPv4 != "" {
			return nil, errors.New("UDP route is bound to IPv4 only; refusing unbound IPv6 destination")
		}
		if ip.Is4() && directBind.ListenIPv4 == "" && directBind.ListenIPv6 != "" {
			return nil, errors.New("UDP route is bound to IPv6 only; refusing unbound IPv4 destination")
		}
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
	outType := strings.ToLower(out.Type)
	if out.TLS || outType == "trojan" || outType == "https" {
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

	if strings.ToLower(out.Network) == "ws" {
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
	default:
		c.Close()
		return nil, fmt.Errorf("socks5 connect: unsupported ATYP 0x%02x", rhead[3])
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
	readMu    sync.Mutex
	readHdr   bool
	hdrBuf    [2]byte
	hdrRead   int
	hdrParsed bool
	addonRem  int
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
	for !v.readHdr {
		if !v.hdrParsed {
			for v.hdrRead < 2 {
				n, err := v.Conn.Read(v.hdrBuf[v.hdrRead:2])
				v.hdrRead += n
				if v.hdrRead >= 2 {
					break
				}
				if err != nil {
					v.readMu.Unlock()
					return 0, err
				}
			}
			v.hdrParsed = true
			v.addonRem = int(v.hdrBuf[1])
		}
		for v.addonRem > 0 {
			var discard [256]byte
			want := v.addonRem
			if want > len(discard) {
				want = len(discard)
			}
			n, err := v.Conn.Read(discard[:want])
			v.addonRem -= n
			if v.addonRem <= 0 {
				break
			}
			if err != nil {
				v.readMu.Unlock()
				return 0, err
			}
		}
		v.readHdr = true
	}
	v.readMu.Unlock()
	return v.Conn.Read(p)
}

func dialNodeShadowsocks(ctx context.Context, out acl.OutboundNode, targetHost string, targetPort uint16, resolver *dns.Resolver, timeout time.Duration) (net.Conn, error) {
	keyLen := 32
	isChaCha := false
	switch strings.ToLower(strings.TrimSpace(out.Cipher)) {
	case "", "aes-256-gcm":
		keyLen = 32
	case "aes-128-gcm":
		keyLen = 16
	case "chacha20-ietf-poly1305", "chacha20-poly1305":
		keyLen = 32
		isChaCha = true
	default:
		return nil, fmt.Errorf("unsupported shadowsocks outbound cipher %q", out.Cipher)
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

	writeMu     sync.Mutex
	writeAEAD   cipher.AEAD
	writeNonce  [12]byte
	unsentWire  []byte
	writeBroken bool

	readMu    sync.Mutex
	readAEAD  cipher.AEAD
	readNonce [12]byte
	saltBuf   [32]byte
	saltRead  int
	lenBuf    [18]byte
	lenRead   int
	chunkBuf  *[]byte
	chunkNeed int
	chunkRead int
	leftover  []byte
}

func (s *ssClientConn) Close() error {
	err := s.Conn.Close()
	s.readMu.Lock()
	if s.chunkBuf != nil {
		bufpool.Put(s.chunkBuf)
		s.chunkBuf = nil
		s.chunkNeed = 0
		s.chunkRead = 0
	}
	s.readMu.Unlock()
	return err
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

func (s *ssClientConn) drainUnsentLocked() error {
	for len(s.unsentWire) > 0 {
		nw, err := s.Conn.Write(s.unsentWire)
		if nw > 0 {
			s.unsentWire = s.unsentWire[nw:]
		}
		if err != nil {
			return err
		}
		if nw == 0 {
			return io.ErrShortWrite
		}
	}
	s.unsentWire = nil
	return nil
}

func (s *ssClientConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.writeBroken {
		return 0, errors.New("ss outbound write stream desynchronized after partial write")
	}
	if err := s.drainUnsentLocked(); err != nil {
		return 0, err
	}

	origLen := len(p)
	hasHdr := len(s.pendingHdr) > 0
	hdrLen := len(s.pendingHdr)
	work := p
	if hasHdr {
		combined := make([]byte, 0, hdrLen+len(p))
		combined = append(combined, s.pendingHdr...)
		combined = append(combined, p...)
		work = combined
	}

	sentPayload := 0
	for len(work) > 0 {
		chunk := work
		if len(chunk) > 0x3FFF {
			chunk = work[:0x3FFF]
		}
		work = work[len(chunk):]

		aead := s.writeAEAD
		var prefixSalt []byte
		if aead == nil {
			prefixSalt = make([]byte, s.keyLen)
			if _, err := rand.Read(prefixSalt); err != nil {
				return sentPayload, err
			}
			var err error
			aead, err = s.makeSubAEAD(prefixSalt)
			if err != nil {
				return sentPayload, err
			}
		}

		nextNonce := s.writeNonce
		bp := bufpool.Get(len(prefixSalt) + 2 + 16 + len(chunk) + 16)
		out := (*bp)[:0]
		if len(prefixSalt) > 0 {
			out = append(out, prefixSalt...)
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(chunk)))
		out = aead.Seal(out, nextNonce[:], lb[:], nil)
		incSSNonce(&nextNonce)
		out = aead.Seal(out, nextNonce[:], chunk, nil)
		incSSNonce(&nextNonce)

		nw, err := s.Conn.Write(out)
		if nw == 0 && err != nil {
			// Nothing hit the wire: keep pendingHdr, writeAEAD, and writeNonce completely intact.
			bufpool.Put(bp)
			return sentPayload, err
		}
		// At least 1 byte hit the wire: commit cipher state & header consumption.
		s.writeAEAD = aead
		s.writeNonce = nextNonce
		if hasHdr {
			s.pendingHdr = nil
			hasHdr = false
		}
		if nw < len(out) {
			s.unsentWire = append([]byte(nil), out[nw:]...)
			s.writeBroken = true
			bufpool.Put(bp)
			if err == nil {
				err = io.ErrShortWrite
			}
			return sentPayload, err
		}
		bufpool.Put(bp)
		if err != nil {
			return sentPayload, err
		}
		if hdrLen > 0 {
			if len(chunk) <= hdrLen {
				hdrLen -= len(chunk)
			} else {
				sentPayload += len(chunk) - hdrLen
				hdrLen = 0
			}
		} else {
			sentPayload += len(chunk)
		}
	}
	return origLen, nil
}

func (s *ssClientConn) flushTargetHeaderIfNeeded() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeBroken {
		return errors.New("ss outbound write stream desynchronized after partial write")
	}
	if err := s.drainUnsentLocked(); err != nil {
		return err
	}
	if len(s.pendingHdr) == 0 {
		return nil
	}
	hdr := s.pendingHdr

	aead := s.writeAEAD
	var prefixSalt []byte
	if aead == nil {
		prefixSalt = make([]byte, s.keyLen)
		if _, err := rand.Read(prefixSalt); err != nil {
			return err
		}
		var err error
		aead, err = s.makeSubAEAD(prefixSalt)
		if err != nil {
			return err
		}
	}

	nextNonce := s.writeNonce
	bp := bufpool.Get(len(prefixSalt) + 2 + 16 + len(hdr) + 16)
	out := (*bp)[:0]
	if len(prefixSalt) > 0 {
		out = append(out, prefixSalt...)
	}
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(hdr)))
	out = aead.Seal(out, nextNonce[:], lb[:], nil)
	incSSNonce(&nextNonce)
	out = aead.Seal(out, nextNonce[:], hdr, nil)
	incSSNonce(&nextNonce)

	nw, werr := s.Conn.Write(out)
	if nw == 0 && werr != nil {
		bufpool.Put(bp)
		return werr
	}
	s.writeAEAD = aead
	s.writeNonce = nextNonce
	s.pendingHdr = nil
	if nw < len(out) {
		s.unsentWire = append([]byte(nil), out[nw:]...)
		bufpool.Put(bp)
		if werr == nil {
			werr = io.ErrShortWrite
		}
		return werr
	}
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
		for s.saltRead < s.keyLen {
			n, err := s.Conn.Read(s.saltBuf[s.saltRead:s.keyLen])
			s.saltRead += n
			if s.saltRead >= s.keyLen {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		aead, err := s.makeSubAEAD(s.saltBuf[:s.keyLen])
		if err != nil {
			return 0, err
		}
		s.readAEAD = aead
	}

	if s.chunkBuf == nil {
		for s.lenRead < 18 {
			n, err := s.Conn.Read(s.lenBuf[s.lenRead:18])
			s.lenRead += n
			if s.lenRead >= 18 {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		var lb [2]byte
		if _, err := s.readAEAD.Open(lb[:0], s.readNonce[:], s.lenBuf[:], nil); err != nil {
			s.lenRead = 0
			return 0, err
		}
		s.lenRead = 0
		incSSNonce(&s.readNonce)
		cLen := int(binary.BigEndian.Uint16(lb[:]) & 0x3FFF)
		if cLen == 0 {
			return 0, io.EOF
		}
		s.chunkBuf = bufpool.Get(cLen + 16)
		s.chunkNeed = cLen + 16
		s.chunkRead = 0
	}

	enc := (*s.chunkBuf)[:s.chunkNeed]
	for s.chunkRead < s.chunkNeed {
		n, err := s.Conn.Read(enc[s.chunkRead:s.chunkNeed])
		s.chunkRead += n
		if s.chunkRead >= s.chunkNeed {
			break
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, err
			}
			bufpool.Put(s.chunkBuf)
			s.chunkBuf = nil
			s.chunkNeed = 0
			s.chunkRead = 0
			return 0, err
		}
	}

	bp := s.chunkBuf
	need := s.chunkNeed
	s.chunkBuf = nil
	s.chunkNeed = 0
	s.chunkRead = 0
	defer bufpool.Put(bp)

	plain, err := s.readAEAD.Open((*bp)[:0], s.readNonce[:], (*bp)[:need], nil)
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

	h := sha1.New()
	_, _ = h.Write([]byte(wsKey))
	_, _ = h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	path := out.WSPath
	if path == "" {
		path = "/"
	}
	host := out.SNI
	if host == "" {
		host = out.Server
	}
	// RFC 3986 / RFC 7230: bare IPv6 literals in Host header must be bracketed.
	if ip, ierr := netip.ParseAddr(strings.Trim(host, "[]")); ierr == nil && ip.Is6() {
		host = "[" + ip.String() + "]"
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
	gotAccept := ""
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
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "sec-websocket-accept") {
			gotAccept = strings.TrimSpace(v)
		}
	}
	if gotAccept != expectedAccept {
		return nil, errors.New("outbound websocket Sec-WebSocket-Accept mismatch")
	}
	return &wsClientConn{Conn: c, br: br}, nil
}

type wsClientConn struct {
	net.Conn
	br *bufio.Reader

	readMu      sync.Mutex
	frameRem    int64
	masked      bool
	maskKey     [4]byte
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

func (w *wsClientConn) SetWriteDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	err := w.Conn.SetWriteDeadline(t)
	w.deadlineMu.Unlock()
	return err
}

func (w *wsClientConn) SetDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	err := w.Conn.SetDeadline(t)
	w.deadlineMu.Unlock()
	return err
}

func (w *wsClientConn) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
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
		op := w.hdrBuf[0] & 0x0F
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
		var plen int64
		switch lenCode {
		case 126:
			plen = int64(binary.BigEndian.Uint16(w.hdrBuf[pos : pos+2]))
			pos += 2
		case 127:
			plen = int64(binary.BigEndian.Uint64(w.hdrBuf[pos : pos+8]))
			pos += 8
			if plen < 0 || plen > 16*1024*1024 {
				return 0, errors.New("outbound websocket frame too large")
			}
		default:
			plen = int64(lenCode)
		}
		if op >= 0x8 && plen > 125 {
			return 0, errors.New("outbound websocket control frame exceeds 125 bytes")
		}
		var mkey [4]byte
		if masked {
			copy(mkey[:], w.hdrBuf[pos:pos+4])
		}
		if op == 0x8 {
			return 0, io.EOF
		}
		if op == 0x9 { // Ping -> reply masked Pong with bounded write deadline
			if plen == 0 {
				_ = w.writeControlFrame(0xA, nil)
			} else {
				w.ctrlOp = 0x9
				w.ctrlRem = plen
				w.ctrlMasked = masked
				w.ctrlMaskKey = mkey
				w.ctrlRead = 0
			}
			continue
		}
		if op == 0x1 || op == 0x2 || op == 0x0 {
			w.frameRem = plen
			w.masked = masked
			w.maskKey = mkey
			w.maskPos = 0
		} else if plen > 0 {
			w.ctrlOp = 0xFF
			w.ctrlRem = plen
		}
	}
	toRead := int64(len(p))
	if toRead > w.frameRem {
		toRead = w.frameRem
	}
	n, err := w.br.Read(p[:toRead])
	if n > 0 {
		if w.masked {
			for i := 0; i < n; i++ {
				p[i] ^= w.maskKey[w.maskPos&3]
				w.maskPos++
			}
		}
		w.frameRem -= int64(n)
	}
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

func (w *wsClientConn) writeControlFrame(opcode byte, p []byte) error {
	if len(p) > 125 {
		p = p[:125]
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
	return w.writeClientFrameLocked(opcode, p)
}

func (w *wsClientConn) writeClientFrame(opcode byte, p []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.writeClientFrameLocked(opcode, p)
}

func (w *wsClientConn) writeClientFrameLocked(opcode byte, p []byte) error {
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

// DialUDPForRoute opens a PacketConn honoring `route.Outbounds` strictly:
// - `block` rejects UDP.
// - `socks5` uses SOCKS5 `UDP ASSOCIATE`.
// - `direct` honors single-family `listen_ipv4`/`listen_ipv6` bindings without leaking the opposite family.
// - Non-SOCKS5 proxy routes or failed SOCKS5 routes NEVER silently fall back to direct egress.
func DialUDPForRoute(ctx context.Context, route acl.OutboundTarget, preferIPv6 bool, resolver *dns.Resolver) (net.PacketConn, error) {
	if route.Action == acl.ActionBlock {
		return nil, errors.New("UDP blocked by ACL/audit rule")
	}
	if len(route.Outbounds) == 0 {
		return net.ListenPacket("udp", "")
	}

	var lastErr error
	for _, out := range route.Outbounds {
		switch strings.ToLower(out.Type) {
		case "block":
			return nil, errors.New("UDP blocked by route outbound")
		case "socks5", "socks":
			pc, err := dialSOCKS5UDPAssociate(ctx, out, resolver, 5*time.Second)
			if err == nil {
				return pc, nil
			}
			lastErr = err
		case "direct", "":
			if preferIPv6 {
				if out.ListenIPv6 != "" {
					ip := net.ParseIP(strings.Trim(out.ListenIPv6, "[]"))
					if ip == nil || ip.To4() != nil {
						lastErr = fmt.Errorf("invalid UDP route listen_ipv6 %q", out.ListenIPv6)
						continue
					}
					pc, err := net.ListenPacket("udp6", net.JoinHostPort(ip.String(), "0"))
					if err == nil {
						return pc, nil
					}
					lastErr = err
					continue
				} else if out.ListenIPv4 != "" {
					lastErr = errors.New("UDP route is bound to IPv4 only; refusing unbound IPv6 socket")
					continue
				}
			} else {
				if out.ListenIPv4 != "" {
					ip := net.ParseIP(strings.Trim(out.ListenIPv4, "[]"))
					if ip == nil || ip.To4() == nil {
						lastErr = fmt.Errorf("invalid UDP route listen_ipv4 %q", out.ListenIPv4)
						continue
					}
					pc, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "0"))
					if err == nil {
						return pc, nil
					}
					lastErr = err
					continue
				} else if out.ListenIPv6 != "" {
					lastErr = errors.New("UDP route is bound to IPv6 only; refusing unbound IPv4 socket")
					continue
				}
			}
			pc, err := net.ListenPacket("udp", "")
			if err == nil {
				return pc, nil
			}
			lastErr = err
		default:
			lastErr = fmt.Errorf("UDP relay unsupported for outbound type %q", out.Type)
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no UDP-capable outbound available for route")
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
		// Resolve domain BND.ADDR to IP respecting ctx so relayAddr is usable
		domainName := string(b[:l[0]])
		bndPort = int(binary.BigEndian.Uint16(b[l[0]:]))
		if resolver != nil {
			if addr, rerr := resolver.Resolve(ctx, domainName, dns.StrategyIPv4First, false); rerr == nil && addr.IsValid() {
				bndIP = net.IP(addr.AsSlice())
			}
		}
		if len(bndIP) == 0 {
			if ips, lerr := net.DefaultResolver.LookupIPAddr(ctx, domainName); lerr == nil && len(ips) > 0 {
				bndIP = ips[0].IP
			}
		}
	default:
		c.Close()
		return nil, errors.New("socks5 udp unknown atyp")
	}
	if bndPort <= 0 {
		c.Close()
		return nil, errors.New("socks5 udp invalid relay port")
	}
	if len(bndIP) == 0 || bndIP.IsUnspecified() {
		if peerIP := ExtractClientIP(c.RemoteAddr()); peerIP.IsValid() && !peerIP.IsUnspecified() {
			bndIP = net.IP(peerIP.AsSlice())
		} else if srvIP, perr := netip.ParseAddr(strings.Trim(out.Server, "[]")); perr == nil && !srvIP.IsUnspecified() {
			bndIP = net.IP(srvIP.Unmap().AsSlice())
		}
	}
	if len(bndIP) == 0 || bndIP.IsUnspecified() {
		c.Close()
		return nil, errors.New("socks5 udp: could not determine relay IP address")
	}
	_ = c.SetDeadline(time.Time{})

	bindNet := "udp4"
	localBind := "0.0.0.0:0"
	if bndIP.To4() == nil {
		bindNet = "udp6"
		localBind = "[::]:0"
	}
	if peerIP := ExtractClientIP(c.RemoteAddr()); peerIP.IsValid() && peerIP.IsLoopback() {
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
	if !ok || ua == nil || ua.IP == nil {
		return 0, errors.New("socks5 udp expects non-nil *net.UDPAddr with valid IP")
	}
	bp := bufpool.Get(24 + len(p))
	defer bufpool.Put(bp)
	pkt := (*bp)[:0]
	pkt = append(pkt, 0x00, 0x00, 0x00) // RSV(2), FRAG=0
	if ip4 := ua.IP.To4(); ip4 != nil {
		pkt = append(pkt, 0x01)
		pkt = append(pkt, ip4...)
	} else if ip16 := ua.IP.To16(); ip16 != nil {
		pkt = append(pkt, 0x04)
		pkt = append(pkt, ip16...)
	} else {
		return 0, errors.New("socks5 udp invalid destination IP")
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
		n, fromAddr, err := s.PacketConn.ReadFrom(raw)
		if err != nil {
			return 0, nil, err
		}
		// Verify packet source matches relay address to prevent UDP injection from spoofed sources
		if s.relayAddr != nil {
			if ua, ok := fromAddr.(*net.UDPAddr); ok {
				if !ua.IP.Equal(s.relayAddr.IP) || ua.Port != s.relayAddr.Port {
					continue
				}
			}
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
			if srcIP == nil {
				// Domain ATYP that doesn't parse as IP — skip packet to avoid nil IP in returned addr
				pos += dlen
				continue
			}
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
