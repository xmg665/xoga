package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/logger"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/sniff"
	"github.com/xmg665/xoga/internal/stats"
	"github.com/xmg665/xoga/internal/transport"
)

// SSUserEntry precomputes Shadowsocks master keys & SS2022 EIH identity blocks once on user sync
// so incoming connections perform zero key-derivation work when unchanged.
type SSUserEntry struct {
	User      *stats.UserEntry
	MasterKey []byte   // derived via EVP_BytesToKey (AEAD) or base64/BLAKE3 (SS2022)
	EIHHash   [16]byte // BLAKE3("shadowsocks 2022 identity subkey", userKey)[:16] for SS2022 EIH
}

// VMessUserEntry precomputes VMess cmdKey (`MD5(UUID + magic)`) and AuthID AES-128 block cipher
// once on user sync so 5,000+ user VMess nodes perform zero KDF or heap allocations per handshake.
type VMessUserEntry struct {
	User      *stats.UserEntry
	CmdKey    [16]byte
	AuthBlock cipher.Block // AES-128 block cipher for `KDF16(cmdKey, "AES Auth ID Encryption")`
}

// UserIndex is an immutable snapshot swapped atomically via atomic.Pointer[UserIndex] (RCU pattern).
// Handshake lookups require ZERO mutex locks regardless of concurrency.
type UserIndex struct {
	Users      []*stats.UserEntry
	ByTrojan   map[[56]byte]*stats.UserEntry
	ByUUID     map[[16]byte]*stats.UserEntry
	SSUsers    []SSUserEntry
	SSEIHMap   map[[16]byte]*SSUserEntry
	VMessUsers []VMessUserEntry
}

func BuildUserIndex(users []*stats.UserEntry, ssKeyLen int) *UserIndex {
	idx := &UserIndex{
		Users:    users,
		ByTrojan: make(map[[56]byte]*stats.UserEntry, len(users)),
		ByUUID:   make(map[[16]byte]*stats.UserEntry, len(users)),
	}
	if ssKeyLen > 0 {
		idx.SSUsers = make([]SSUserEntry, 0, len(users))
		idx.SSEIHMap = make(map[[16]byte]*SSUserEntry, len(users))
	}
	idx.VMessUsers = make([]VMessUserEntry, 0, len(users))

	for _, u := range users {
		idx.ByTrojan[u.TrojanHash] = u
		if u.HasUUID {
			idx.ByUUID[u.UUIDBytes] = u
			cmdKey := vmessCmdKey(u.UUIDBytes)
			authKey := vmessKDF(cmdKey[:], "AES Auth ID Encryption")[:16]
			if blk, err := aes.NewCipher(authKey); err == nil {
				idx.VMessUsers = append(idx.VMessUsers, VMessUserEntry{
					User:      u,
					CmdKey:    cmdKey,
					AuthBlock: blk,
				})
			}
		}
		if ssKeyLen > 0 {
			mk := deriveSSUserKey(u.Passwd, ssKeyLen)
			var eih [16]byte
			blake3DeriveKey("shadowsocks 2022 identity subkey", mk, eih[:])
			entry := SSUserEntry{
				User:      u,
				MasterKey: mk,
				EIHHash:   eih,
			}
			idx.SSUsers = append(idx.SSUsers, entry)
		}
	}
	for i := range idx.SSUsers {
		idx.SSEIHMap[idx.SSUsers[i].EIHHash] = &idx.SSUsers[i]
	}
	return idx
}

func deriveSSUserKey(secret string, keyLen int) []byte {
	if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) >= keyLen {
		out := make([]byte, keyLen)
		copy(out, raw[:keyLen])
		return out
	}
	return evpBytesToKey(secret, keyLen)
}

func evpBytesToKey(password string, keyLen int) []byte {
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

// Server manages the active TCP/TLS/WS listener and UDP packet listener for a node.
type Server struct {
	cfg      *config.Config
	spec     *panel.NodeSpec
	tracker  *stats.Tracker
	dnsRes   *dns.Resolver
	ssSpec   ssCipherSpec
	ssPSK    []byte
	ssPSKBlk cipher.Block

	userIdx atomic.Pointer[UserIndex]
	aclEng  atomic.Pointer[acl.Engine]

	tcpLn   net.Listener
	udpConn net.PacketConn
	tlsProv *transport.TLSProvider

	closed atomic.Bool
	wg     sync.WaitGroup
}

func NewServer(cfg *config.Config, spec *panel.NodeSpec, tracker *stats.Tracker, initialIdx *UserIndex, initialACL *acl.Engine, dnsResolver ...*dns.Resolver) (*Server, error) {
	var res *dns.Resolver
	if len(dnsResolver) > 0 && dnsResolver[0] != nil {
		res = dnsResolver[0]
	} else {
		res = dns.NewResolver(cfg.DNSConfigPath, cfg.DNSConfigURL, cfg.DefaultDNS, cfg.DNSStrategy)
	}
	s := &Server{
		cfg:     cfg,
		spec:    spec,
		tracker: tracker,
		dnsRes:  res,
	}
	s.userIdx.Store(initialIdx)
	s.aclEng.Store(initialACL)

	if spec.Protocol == "shadowsocks" {
		cs, err := parseSSCipher(spec.Cipher)
		if err != nil {
			return nil, err
		}
		s.ssSpec = cs
		if cs.is2022 && spec.ServerKey != "" {
			psk, err := base64.StdEncoding.DecodeString(spec.ServerKey)
			if err != nil || len(psk) < cs.keySize {
				psk = evpBytesToKey(spec.ServerKey, cs.keySize)
			} else {
				psk = psk[:cs.keySize]
			}
			s.ssPSK = psk
			if blk, err := aes.NewCipher(psk); err == nil {
				s.ssPSKBlk = blk
			}
		}
	}
	return s, nil
}

func (s *Server) SSKeySize() int {
	if s.spec.Protocol == "shadowsocks" {
		if cs, err := parseSSCipher(s.spec.Cipher); err == nil {
			return cs.keySize
		}
		return 32
	}
	return 0
}

func (s *Server) UpdateUsers(idx *UserIndex) {
	s.userIdx.Store(idx)
}

func (s *Server) UpdateACL(eng *acl.Engine) {
	s.aclEng.Store(eng)
}

func (s *Server) Start() error {
	listenIP := s.spec.ListenIP
	if s.cfg.ListenIP != "" {
		listenIP = s.cfg.ListenIP
	}
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	port := s.spec.ServerPort
	if s.cfg.ListenPort > 0 {
		port = s.cfg.ListenPort
	}
	if port <= 0 {
		return errors.New("server_port is 0; check panel node configuration")
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(port))

	rawLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}

	ln := rawLn
	if s.cfg.ProxyProtocol {
		ln = &relay.ProxyProtoListener{Listener: ln}
	}

	needTLS := !s.cfg.ForceCloseSSL && (s.spec.TLSMode > 0 || s.cfg.CertFile != "" || s.cfg.CertMode == "http" || s.cfg.CertMode == "self")
	if needTLS {
		tp, err := transport.BuildTLSConfig(s.cfg, s.spec.ServerName)
		if err != nil {
			_ = rawLn.Close()
			return fmt.Errorf("init TLS: %w", err)
		}
		s.tlsProv = tp
		ln = tls.NewListener(ln, tp.Config())
	}
	s.tcpLn = ln

	s.wg.Add(1)
	go s.acceptLoop()

	// Start native UDP listener when running Shadowsocks over raw network
	if s.spec.Protocol == "shadowsocks" && s.spec.Network != "ws" && !needTLS {
		udpConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			logger.Warnf("Shadowsocks UDP listen %s failed (TCP still active): %v", addr, err)
		} else {
			s.udpConn = udpConn
			s.wg.Add(1)
			go s.serveShadowsocksUDP(udpConn)
		}
	}

	logger.Infof("Inbound started: protocol=%s addr=%s network=%s tls=%v zerocopy=%v",
		s.spec.Protocol, addr, s.spec.Network, needTLS, s.cfg.EnableZeroCopy)
	return nil
}

func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	if s.tlsProv != nil {
		s.tlsProv.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	relay.TuneTCP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))

	if s.spec.Network == "ws" {
		wsConn, err := transport.AcceptWebSocket(conn, s.spec.WSPath)
		if err != nil {
			logger.Debugf("ws upgrade failed from %s: %v", conn.RemoteAddr(), err)
			return
		}
		conn = wsConn
	}

	switch s.spec.Protocol {
	case "trojan":
		s.handleTrojan(conn)
	case "vless":
		s.handleVLESS(conn)
	case "shadowsocks":
		s.handleShadowsocksTCP(conn)
	case "vmess":
		s.handleVMess(conn)
	}
}

// connectAndRelay performs first-packet sniffing (TLS SNI / HTTP Host / BitTorrent), ACL routing,
// outbound dialing, and zero-copy or pooled-buffer bidirectional relay.
func (s *Server) connectAndRelay(clientConn net.Conn, user *stats.UserEntry, destHost string, destPort uint16, preread []byte) {
	clientIP := relay.ExtractClientIP(clientConn.RemoteAddr())
	if err := user.AcquireConn(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter()); err != nil {
		logger.Debugf("user %d rejected (%s): %v", user.ID, clientIP, err)
		return
	}
	defer user.ReleaseConn()

	// If no initial payload was read yet, briefly peek up to SmallSize (2 KiB) with a short deadline
	// so TLS ClientHello SNI, HTTP Host, and BitTorrent handshakes are caught before dialing.
	var peeked []byte
	var peekBuf *[]byte
	if len(preread) > 0 {
		peeked = preread
	} else {
		peekBuf = bufpool.Get(bufpool.SmallSize)
		defer bufpool.Put(peekBuf)
		_ = clientConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, err := clientConn.Read((*peekBuf)[:])
		_ = clientConn.SetReadDeadline(time.Time{})
		if n > 0 {
			peeked = (*peekBuf)[:n]
		} else if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				return
			}
		}
	}

	sn := sniff.Inspect(peeked)
	aclEng := s.aclEng.Load()
	route := aclEng.DecideWithPort(destHost, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		logger.Debugf("blocked user=%d dest=%s:%d sni=%s proto=%s rule=%s", user.ID, destHost, destPort, sn.Domain, sn.Protocol, route.RuleName)
		return
	}

	// Domain Sniff Override: if client sent a pre-resolved IP, rewrite destination to the
	// sniffed TLS SNI / HTTP Host when matching a DNS unlock rule, route unlock rule, or force_domain_sniff.
	effectiveHost := destHost
	if sn.Domain != "" && s.cfg.DomainSniff {
		if _, isIP := netip.ParseAddr(destHost); isIP == nil {
			if s.cfg.ForceDomainSniff || route.Action == acl.ActionProxy || s.dnsRes.HasRuleForDomain(sn.Domain) || aclEng.HasRouteForDomain(sn.Domain) {
				effectiveHost = sn.Domain
			}
		}
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remoteConn, err := relay.DialOutbound(dialCtx, effectiveHost, destPort, route, s.dnsRes, 10*time.Second)
	cancel()
	if err != nil {
		logger.Debugf("dial %s:%d (rule=%s) failed: %v", effectiveHost, destPort, route.RuleName, err)
		return
	}
	defer remoteConn.Close()

	idleDur := time.Duration(s.cfg.ConnIdleSec) * time.Second
	if idleDur < 15*time.Second {
		idleDur = 300 * time.Second
	}
	relay.PipeBidirectional(clientConn, remoteConn, peeked, user, s.tracker.NodeLimiter, idleDur, s.cfg.EnableZeroCopy)
}

// parseSOCKS5Addr reads [AddrType(1) + Addr + Port(2)] used by Trojan and Shadowsocks.
func parseSOCKS5Addr(r io.Reader) (host string, port uint16, err error) {
	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case 0x01: // IPv4
		var buf [6]byte
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[0:4]).String()
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03: // Domain
		var dlen [1]byte
		if _, err = io.ReadFull(r, dlen[:]); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(dlen[0])+2)
		if _, err = io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = strings.TrimSpace(string(buf[:dlen[0]]))
		port = binary.BigEndian.Uint16(buf[dlen[0]:])
	case 0x04: // IPv6
		var buf [18]byte
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[0:16]).String()
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		return "", 0, fmt.Errorf("unsupported address type 0x%02x", atyp[0])
	}
	return host, port, nil
}
