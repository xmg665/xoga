package protocol

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

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
	Users       []*stats.UserEntry
	ByTrojan    map[[56]byte]*stats.UserEntry
	ByUUID      map[[16]byte]*stats.UserEntry
	BySHA256    map[[32]byte]*stats.UserEntry // AnyTLS O(1) SHA-256(password/UUID) lookup
	ByPassword  map[string]*stats.UserEntry   // Hysteria2 O(1) password / UUID / id:pass lookup
	SSUsers     []SSUserEntry
	SSEIHMap    map[[16]byte]*SSUserEntry
	VMessUsers  []VMessUserEntry
	VMessBlocks []cipher.Block // compact 16B/user parallel slice for L1/L2 cache-friendly AuthID scan
}

func (idx *UserIndex) LookupPassword(cred string) *stats.UserEntry {
	if idx == nil || cred == "" {
		return nil
	}
	if u, ok := idx.ByPassword[cred]; ok {
		return u
	}
	if _, right, hasColon := strings.Cut(cred, ":"); hasColon && right != "" {
		if u, ok := idx.ByPassword[right]; ok {
			return u
		}
	}
	return nil
}

func BuildUserIndex(users []*stats.UserEntry, ssKeyLen int) *UserIndex {
	return BuildUserIndexForProtocol("", users, ssKeyLen)
}

// BuildUserIndexForProtocol constructs only the lookup structures required by `proto`
// ("vmess", "vless", "trojan", "shadowsocks", "hysteria2", "anytls", or "" for all),
// saving ~35 MiB of unused map buckets across multi-node instances and reusing cached VMess key schedules.
func BuildUserIndexForProtocol(proto string, users []*stats.UserEntry, ssKeyLen int) *UserIndex {
	needTrojan := proto == "" || proto == "trojan"
	needVLESS := proto == "" || proto == "vless"
	needVMess := proto == "" || proto == "vmess"
	needAnyTLS := proto == "" || proto == "anytls"
	needHy2 := proto == "" || proto == "hysteria2"
	needSS := ssKeyLen > 0 || proto == "shadowsocks"

	idx := &UserIndex{
		Users: users,
	}
	if needTrojan {
		idx.ByTrojan = make(map[[56]byte]*stats.UserEntry, len(users))
	}
	if needVLESS {
		idx.ByUUID = make(map[[16]byte]*stats.UserEntry, len(users))
	}
	if needAnyTLS {
		idx.BySHA256 = make(map[[32]byte]*stats.UserEntry, len(users))
	}
	if needHy2 {
		idx.ByPassword = make(map[string]*stats.UserEntry, len(users))
	}
	if needSS && ssKeyLen > 0 {
		idx.SSUsers = make([]SSUserEntry, 0, len(users))
		idx.SSEIHMap = make(map[[16]byte]*SSUserEntry, len(users))
	}
	if needVMess {
		idx.VMessUsers = make([]VMessUserEntry, 0, len(users))
		idx.VMessBlocks = make([]cipher.Block, 0, len(users))
	}

	for _, u := range users {
		if u.IsDisabled() {
			continue
		}
		if needTrojan {
			idx.ByTrojan[u.TrojanHash] = u
			if u.Passwd != "" && u.Passwd != u.UUID {
				var altTrojan [56]byte
				encodeAltTrojanHash(u.Passwd, &altTrojan)
				idx.ByTrojan[altTrojan] = u
			}
		}
		if needAnyTLS {
			idx.BySHA256[u.SHA256UUID] = u
			if u.Passwd != "" && u.Passwd != u.UUID {
				idx.BySHA256[u.SHA256Passwd] = u
			}
		}
		if needHy2 {
			if u.UUID != "" {
				idx.ByPassword[u.UUID] = u
			}
			if u.Passwd != "" {
				idx.ByPassword[u.Passwd] = u
			}
		}
		if u.HasUUID {
			if needVLESS {
				idx.ByUUID[u.UUIDBytes] = u
			}
			if needVMess {
				if !u.VMessAuthReady || u.VMessAuthBlock == nil {
					cmdKey := vmessCmdKey(u.UUIDBytes)
					authKey := vmessKDF(cmdKey[:], "AES Auth ID Encryption")[:16]
					if blk, err := aes.NewCipher(authKey); err == nil {
						u.VMessCmdKey = cmdKey
						u.VMessAuthBlock = blk
						u.VMessAuthReady = true
					}
				}
				if u.VMessAuthReady && u.VMessAuthBlock != nil {
					idx.VMessUsers = append(idx.VMessUsers, VMessUserEntry{
						User:      u,
						CmdKey:    u.VMessCmdKey,
						AuthBlock: u.VMessAuthBlock,
					})
					idx.VMessBlocks = append(idx.VMessBlocks, u.VMessAuthBlock)
				}
			}
		}
		if needSS && ssKeyLen > 0 {
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

func encodeAltTrojanHash(secret string, dst *[56]byte) {
	sum := sha256.Sum224([]byte(secret))
	hex.Encode(dst[:], sum[:])
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

	ipHints ipHintCache
	hotRing hotUserRing
	replay  replayFilter

	userIdx atomic.Pointer[UserIndex]
	aclEng  atomic.Pointer[acl.Engine]

	tcpLn        net.Listener
	udpConn      net.PacketConn
	tlsProv      *transport.TLSProvider
	hy2Transport *quic.Transport
	hy2Listener  *quic.Listener

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
	s.hotRing.Reset()
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

	if s.spec.Protocol == "hysteria2" {
		return s.startHysteria2(addr)
	}

	rawLn, err := listenTCP(context.Background(), addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}

	ln := rawLn
	if s.cfg.ProxyProtocol {
		ln = &relay.ProxyProtoListener{Listener: ln}
	}

	needReality := !s.cfg.ForceCloseSSL && s.spec.TLSMode == 2
	needTLS := !s.cfg.ForceCloseSSL && !needReality && (s.spec.TLSMode > 0 || s.spec.Protocol == "anytls" || s.cfg.CertFile != "" || s.cfg.CertMode == "http" || s.cfg.CertMode == "self")

	if needReality {
		rln, rerr := transport.BuildRealityListener(ln, transport.RealityOptions{
			Dest:        s.spec.RealityDest,
			PrivateKey:  s.spec.RealityPrivateKey,
			ShortIDs:    s.spec.RealityShortIDs,
			ServerNames: s.spec.RealityServerNames,
			FallbackSNI: s.spec.ServerName,
		})
		if rerr != nil {
			_ = rawLn.Close()
			return fmt.Errorf("init REALITY: %w", rerr)
		}
		ln = rln
	} else if needTLS {
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

	// Start native UDP listener when running classic AEAD Shadowsocks over raw network
	if s.spec.Protocol == "shadowsocks" && !s.ssSpec.is2022 && s.spec.Network != "ws" && !needTLS && !needReality {
		udpConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			logger.Warnf("Shadowsocks UDP listen %s failed (TCP still active): %v", addr, err)
		} else {
			s.udpConn = udpConn
			s.wg.Add(1)
			go s.serveShadowsocksUDP(udpConn)
		}
	}

	logger.Infof("Inbound started: protocol=%s addr=%s network=%s tls=%v reality=%v zerocopy=%v",
		s.spec.Protocol, addr, s.spec.Network, needTLS, needReality, s.cfg.EnableZeroCopy)
	return nil
}

func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.hy2Listener != nil {
		_ = s.hy2Listener.Close()
	}
	if s.hy2Transport != nil {
		_ = s.hy2Transport.Close()
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
	case "anytls":
		s.handleAnyTLS(conn)
	}
}

// connectAndRelay acquires a tracked user session (so account expiry / quota exhaustion immediately
// severs the active socket via `DisableAndKick`), then sniffs, routes, dials, and relays.
func (s *Server) connectAndRelay(clientConn net.Conn, user *stats.UserEntry, destHost string, destPort uint16, preread []byte) {
	clientIP := relay.ExtractClientIP(clientConn.RemoteAddr())
	connID, err := user.AcquireSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), clientConn)
	if err != nil {
		logger.Debugf("user %d rejected (%s): %v", user.ID, clientIP, err)
		return
	}
	defer user.ReleaseSession(connID)

	s.connectStreamNoAcquire(clientConn, user, destHost, destPort, preread, nil)
}

func (s *Server) connectStreamNoAcquire(
	clientConn net.Conn,
	user *stats.UserEntry,
	destHost string,
	destPort uint16,
	preread []byte,
	onDial func(error),
) {
	if user == nil || user.IsDisabled() {
		if onDial != nil {
			onDial(stats.ErrUserDisabled)
		}
		return
	}

	// For multiplexed AnyTLS v2 (`onDial != nil`), client waits for `cmdSYNACK` BEFORE sending first application payload!
	// So only peek prior to dialing when `onDial == nil`.
	var peeked []byte
	var peekBuf *[]byte
	if len(preread) > 0 {
		peeked = preread
	} else if onDial == nil {
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
	route := aclEng.DecideForNode(s.cfg.NodeID, destHost, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		logger.Debugf("blocked user=%d dest=%s:%d sni=%s proto=%s rule=%s", user.ID, destHost, destPort, sn.Domain, sn.Protocol, route.RuleName)
		if onDial != nil {
			onDial(errors.New("blocked by audit policy"))
		}
		return
	}

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
	if onDial != nil {
		onDial(err)
	}
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
