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
	EIHHash   [16]byte // BLAKE3::hash(userKey)[:16] for SS2022 EIH (SIP022)
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
	ssExactMode bool
	ssCipher    string
	VMessUsers  []VMessUserEntry
	VMessBlocks []cipher.Block   // compact 16B/user parallel slice for L1/L2 cache-friendly AuthID scan
	VMessByUUID map[[16]byte]int // pointer-free O(1) UUID -> VMessUsers slice index for per-node legacy membership check
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
	return buildUserIndexInternal("", "", users, ssKeyLen, false, false)
}

// BuildUserIndexForCipher constructs lookup structures using exact Shadowsocks cipher semantics
// (SIP004 `EVP_BytesToKey` for classic AEAD vs SIP022 base64 / UUID-prefix for Shadowsocks-2022).
func BuildUserIndexForCipher(proto, cipherName string, users []*stats.UserEntry) *UserIndex {
	ssKeyLen := 0
	is2022 := false
	if proto == "shadowsocks" {
		if cs, err := parseSSCipher(cipherName); err == nil {
			ssKeyLen = cs.keySize
			is2022 = cs.is2022
		} else {
			ssKeyLen = 32
		}
	}
	return buildUserIndexInternal(proto, strings.ToLower(strings.TrimSpace(cipherName)), users, ssKeyLen, is2022, true)
}

// BuildUserIndexForProtocol constructs only the lookup structures required by `proto`
// ("vmess", "vless", "trojan", "shadowsocks", "hysteria2", "anytls", or "" for all),
// saving ~35 MiB of unused map buckets across multi-node instances and reusing cached VMess key schedules.
func BuildUserIndexForProtocol(proto string, users []*stats.UserEntry, ssKeyLen int) *UserIndex {
	return buildUserIndexInternal(proto, "", users, ssKeyLen, false, false)
}

func buildUserIndexInternal(proto, cipherName string, users []*stats.UserEntry, ssKeyLen int, ssIs2022, exactSS bool) *UserIndex {
	needTrojan := proto == "" || proto == "trojan"
	needVLESS := proto == "" || proto == "vless"
	needVMess := proto == "" || proto == "vmess"
	needAnyTLS := proto == "" || proto == "anytls"
	needHy2 := proto == "" || proto == "hysteria2"
	needSS := ssKeyLen > 0 || proto == "shadowsocks"

	idx := &UserIndex{
		Users:       users,
		ssExactMode: exactSS,
		ssCipher:    cipherName,
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
		idx.VMessByUUID = make(map[[16]byte]int, len(users))
	}

	seenID := make(map[int]struct{}, len(users))
	for _, u := range users {
		if u == nil || u.IsDisabled() {
			continue
		}
		if u.ID > 0 {
			if _, dup := seenID[u.ID]; dup {
				continue
			}
			seenID[u.ID] = struct{}{}
		}
		if needTrojan && (u.UUID != "" || u.Passwd != "") {
			idx.ByTrojan[u.TrojanHash] = u
			if u.UUID != "" && u.UUID != u.Passwd {
				var altTrojan [56]byte
				encodeAltTrojanHash(u.UUID, &altTrojan)
				idx.ByTrojan[altTrojan] = u
			}
			if u.Passwd != "" && u.Passwd != u.UUID {
				var altTrojan [56]byte
				encodeAltTrojanHash(u.Passwd, &altTrojan)
				idx.ByTrojan[altTrojan] = u
			}
		}
		if needAnyTLS {
			if u.UUID != "" {
				idx.BySHA256[u.SHA256UUID] = u
			}
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
			if needVMess && u.VMessAuthReady && u.VMessAuthBlock != nil {
				idx.VMessByUUID[u.UUIDBytes] = len(idx.VMessUsers)
				idx.VMessUsers = append(idx.VMessUsers, VMessUserEntry{
					User:      u,
					CmdKey:    u.VMessCmdKey,
					AuthBlock: u.VMessAuthBlock,
				})
				idx.VMessBlocks = append(idx.VMessBlocks, u.VMessAuthBlock)
			}
		}
		if needSS && ssKeyLen > 0 {
			secret := u.Passwd
			if secret == "" {
				secret = u.UUID
			}
			if secret == "" {
				continue
			}
			var mk []byte
			if exactSS {
				mk = deriveSSKeyExact(secret, ssKeyLen, ssIs2022)
			} else {
				mk = deriveSSUserKey(secret, ssKeyLen)
			}
			var eih [16]byte
			blake3Hash("shadowsocks 2022 identity subkey", mk, eih[:])
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

func deriveSSKeyExact(secret string, keyLen int, is2022 bool) []byte {
	if !is2022 {
		// Classic SIP004 AEAD ciphers always derive master keys via EVP_BytesToKey (never base64!)
		return evpBytesToKey(secret, keyLen)
	}
	// SIP022 (Shadowsocks-2022): try standard base64 PSK first, then V2Board/Xboard UUID byte prefix!
	if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) >= keyLen {
		out := make([]byte, keyLen)
		copy(out, raw[:keyLen])
		return out
	}
	if !strings.Contains(secret, "-") {
		if raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(secret, "=")); err == nil && len(raw) >= keyLen {
			out := make([]byte, keyLen)
			copy(out, raw[:keyLen])
			return out
		}
	}
	if len(secret) >= keyLen {
		out := make([]byte, keyLen)
		copy(out, secret[:keyLen])
		return out
	}
	return evpBytesToKey(secret, keyLen)
}

func deriveSSUserKey(secret string, keyLen int) []byte {
	if strings.HasSuffix(secret, "=") {
		if raw, err := base64.StdEncoding.DecodeString(secret); err == nil && len(raw) == keyLen {
			out := make([]byte, keyLen)
			copy(out, raw)
			return out
		}
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
	cfg               *config.Config
	spec              *panel.NodeSpec
	tracker           *stats.Tracker
	dnsRes            *dns.Resolver
	ssSpec            ssCipherSpec
	ssPSK             []byte
	ssPSKBlk          cipher.Block
	trustedProxyCIDRs []netip.Prefix

	ipHints ipHintCache
	hotRing hotUserRing
	replay  replayFilter
	legacy  legacyAuthCache

	userIdx atomic.Pointer[UserIndex]
	aclEng  atomic.Pointer[acl.Engine]

	tcpLn        net.Listener
	udpConn      net.PacketConn
	tlsProv      *transport.TLSProvider
	hy2Transport *quic.Transport
	hy2Listener  *quic.Listener

	closed      atomic.Bool
	wg          sync.WaitGroup
	connsMu     sync.Mutex
	nextSrvConn uint64
	activeConns map[uint64]io.Closer

	// testIdleOverride is used solely by unit tests in package protocol to exercise
	// idle timeout survival paths without waiting 10-30s; always 0 in production.
	testIdleOverride time.Duration
}

func (s *Server) connIdleDur(minFloor, fallback time.Duration) time.Duration {
	if s.testIdleOverride > 0 {
		return s.testIdleOverride
	}
	d := time.Duration(s.cfg.ConnIdleSec) * time.Second
	if d < minFloor {
		return fallback
	}
	return d
}

func (s *Server) udpIdleDur(minFloor, fallback time.Duration) time.Duration {
	if s.testIdleOverride > 0 {
		return s.testIdleOverride
	}
	d := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if d < minFloor {
		return fallback
	}
	return d
}

func (s *Server) trackConn(c io.Closer) uint64 {
	if s.closed.Load() {
		_ = c.Close()
		return 0
	}
	s.connsMu.Lock()
	if s.closed.Load() {
		s.connsMu.Unlock()
		_ = c.Close()
		return 0
	}
	if s.activeConns == nil {
		s.activeConns = make(map[uint64]io.Closer, 32)
	}
	s.nextSrvConn++
	id := s.nextSrvConn
	s.activeConns[id] = c
	s.connsMu.Unlock()
	return id
}

func (s *Server) untrackConn(id uint64) {
	if id == 0 {
		return
	}
	s.connsMu.Lock()
	if s.activeConns != nil {
		delete(s.activeConns, id)
	}
	s.connsMu.Unlock()
}

func NewServer(cfg *config.Config, spec *panel.NodeSpec, tracker *stats.Tracker, initialIdx *UserIndex, initialACL *acl.Engine, dnsResolver ...*dns.Resolver) (*Server, error) {
	var res *dns.Resolver
	if len(dnsResolver) > 0 && dnsResolver[0] != nil {
		res = dnsResolver[0]
	} else {
		res = dns.NewResolver(cfg.DNSConfigPath, cfg.DNSConfigURL, cfg.DefaultDNS, cfg.DNSStrategy)
	}
	trustedCIDRs, invalidCIDRs := transport.ParseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if len(invalidCIDRs) > 0 {
		logger.Warnf("[node %d] Ignoring invalid trusted_proxy_cidrs entries: %v", cfg.NodeID, invalidCIDRs)
	}
	s := &Server{
		cfg:               cfg,
		spec:              spec,
		tracker:           tracker,
		dnsRes:            res,
		trustedProxyCIDRs: trustedCIDRs,
	}
	s.aclEng.Store(initialACL)

	if spec.Protocol == "shadowsocks" {
		cs, err := parseSSCipher(spec.Cipher)
		if err != nil {
			return nil, err
		}
		s.ssSpec = cs
		if initialIdx != nil && (!initialIdx.ssExactMode || initialIdx.ssCipher != cs.name) {
			initialIdx = BuildUserIndexForCipher("shadowsocks", spec.Cipher, initialIdx.Users)
		}
		if cs.is2022 && spec.ServerKey != "" {
			psk := deriveSSKeyExact(spec.ServerKey, cs.keySize, true)
			s.ssPSK = psk
			if blk, err := aes.NewCipher(psk); err == nil {
				s.ssPSKBlk = blk
			}
		}
	}
	s.userIdx.Store(initialIdx)
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
	s.legacy.sync(idx)
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
		return err
	}

	ln := rawLn
	if s.cfg.ProxyProtocol {
		ln = &relay.ProxyProtoListener{
			Listener:      ln,
			RequireHeader: s.cfg.ForceProxyProtocol,
		}
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

	if s.spec.Protocol == "vmess" && s.cfg.VMessAuthMode != "aead" {
		s.legacy.start(s.userIdx.Load)
		logger.Infof("[node %d] VMess auth mode: auto (AEAD + legacy MD5)", s.cfg.NodeID)
	}

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

	logger.Infof("Inbound started: node=%d protocol=%s addr=%s network=%s tls=%v reality=%v zerocopy=%v",
		s.cfg.NodeID, s.spec.Protocol, addr, s.spec.Network, needTLS, needReality, s.cfg.EnableZeroCopy)
	return nil
}

func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.legacy.close()
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
	s.connsMu.Lock()
	conns := s.activeConns
	s.activeConns = nil
	s.connsMu.Unlock()
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
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
			if (errors.As(err, &ne) && ne.Temporary()) || strings.Contains(err.Error(), "too many open files") {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	cid := s.trackConn(conn)
	if cid == 0 {
		return
	}
	defer func() {
		s.untrackConn(cid)
		_ = conn.Close()
	}()
	relay.TuneTCP(conn)
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	if s.spec.Network == "ws" {
		// Never conflate L4 ProxyProtocol with L7 HTTP forwarded headers: L4 relays pass
		// real client IP via PROXY header and do not strip client-spoofed CF-Connecting-IP/XFF.
		// Trust forwarded headers only when trust_forwarded_ip=true, peer is loopback/private,
		// or peer matches explicitly configured trusted_proxy_cidrs.
		wsConn, err := transport.AcceptWebSocketWithTrustedProxies(conn, s.spec.WSPath, s.cfg.TrustForwardedIP, s.trustedProxyCIDRs)
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

// peekInitialPayload reads up to 8 KiB of initial client payload within 150ms (reassembling
// fragmented post-quantum TLS ClientHello records such as X25519MLKEM768) and IMMEDIATELY
// returns the pooled buffer so idle streams never pin slabs in `bufpool`!
func (s *Server) peekInitialPayload(clientConn net.Conn) ([]byte, error) {
	return s.peekInitialPayloadWithTimeout(clientConn, 150*time.Millisecond)
}

func (s *Server) peekInitialPayloadWithTimeout(clientConn net.Conn, wait time.Duration) ([]byte, error) {
	bp := bufpool.Get(8192)
	defer bufpool.Put(bp)

	deadline := time.Now().Add(wait)
	_ = clientConn.SetReadDeadline(deadline)
	defer func() { _ = clientConn.SetReadDeadline(time.Time{}) }()

	buf := *bp
	n, err := clientConn.Read(buf)
	if n == 0 {
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, nil
			}
			return nil, err
		}
		return nil, nil
	}

	// Reassemble fragmented / post-quantum TLS ClientHello records within same wait budget
	for attempt := 0; attempt < 8 && n < len(buf); attempt++ {
		needMore := false
		if n < 5 && buf[0] == 0x16 {
			needMore = true
		} else if n >= 5 && buf[0] == 0x16 && buf[1] == 0x03 {
			recLen := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
			if n < recLen && recLen <= len(buf) {
				needMore = true
			}
		}
		if !needMore {
			break
		}
		m, rerr := clientConn.Read(buf[n:])
		n += m
		if rerr != nil || m == 0 {
			break
		}
	}

	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// readFullActive reads exactly len(buf) bytes from r while preserving partial progress across
// idle read timeouts whenever bidirectional activity (lastActive) is within idleDur.
func readFullActive(conn net.Conn, r io.Reader, buf []byte, idleDur time.Duration, lastActive *atomic.Int64, isDisabled func() bool) error {
	off := 0
	for off < len(buf) {
		if isDisabled != nil && isDisabled() {
			return stats.ErrUserDisabled
		}
		_ = conn.SetReadDeadline(time.Now().Add(idleDur))
		n, err := r.Read(buf[off:])
		off += n
		if n > 0 && lastActive != nil {
			lastActive.Store(time.Now().UnixNano())
		}
		if off >= len(buf) {
			return nil
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && (isDisabled == nil || !isDisabled()) &&
				lastActive != nil && time.Since(time.Unix(0, lastActive.Load())) < idleDur {
				continue
			}
			return err
		}
	}
	return nil
}

// discardActive discards exactly n bytes from r while staying timeout-resumable on active streams.
func discardActive(conn net.Conn, r io.Reader, n int, idleDur time.Duration, lastActive *atomic.Int64, isDisabled func() bool) error {
	if n <= 0 {
		return nil
	}
	var scratch [1024]byte
	rem := n
	for rem > 0 {
		want := rem
		if want > len(scratch) {
			want = len(scratch)
		}
		if err := readFullActive(conn, r, scratch[:want], idleDur, lastActive, isDisabled); err != nil {
			return err
		}
		rem -= want
	}
	return nil
}

// udpRouteKey builds a stable key identifying the outbound UDP socket class (address family +
// route outbound list) so multi-destination UDP sessions reuse sockets per route+family without
// sticking IPv6 or proxy-routed packets onto an unrelated IPv4/direct socket.
func udpRouteKey(route acl.OutboundTarget, isIPv6 bool) string {
	fam := "4"
	if isIPv6 {
		fam = "6"
	}
	if len(route.Outbounds) == 0 {
		return "direct:" + fam
	}
	var sb strings.Builder
	sb.WriteString(fam)
	for _, o := range route.Outbounds {
		sb.WriteByte('|')
		sb.WriteString(strings.ToLower(o.Type))
		sb.WriteByte(':')
		sb.WriteString(o.Server)
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(o.Port))
		sb.WriteByte(':')
		sb.WriteString(o.Username)
		sb.WriteByte(':')
		sb.WriteString(o.Password)
		sb.WriteByte(':')
		sb.WriteString(o.ListenIPv4)
		sb.WriteByte(':')
		sb.WriteString(o.ListenIPv6)
		sb.WriteByte(':')
		sb.WriteString(o.ListenStrategy)
	}
	return sb.String()
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

// resolveEffectiveHost applies Soga/Xray-compatible domain_sniff (`destOverride: ["http","tls"]`,
// `routeOnly=false`): whenever domain_sniff (or force_domain_sniff) is enabled, destHost is a
// literal IP not explicitly whitelisted in `whiteList`, and a valid non-IP SNI/HTTP Host was
// sniffed, override effectiveHost with sniffDomain BEFORE ACL and literal ban_private_ip checks
// so Clash Fake-IPs (198.18.0.0/15), GFW-poisoned IPs (127.0.0.1 / 0.0.0.1), and unreachable
// IPv6 literals resolve via DNS while explicitly whitelisted backend IPs remain directly reachable.
func (s *Server) resolveEffectiveHost(aclEng *acl.Engine, destHost, sniffDomain string) string {
	if sniffDomain != "" && (s.cfg.DomainSniff || s.cfg.ForceDomainSniff) {
		if ip, err := netip.ParseAddr(strings.Trim(destHost, "[]")); err == nil {
			if aclEng != nil && aclEng.IsIPWhitelisted(ip) {
				return destHost
			}
			return sniffDomain
		}
	}
	return destHost
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

	// Short-circuit O(1) forbidden_ports BEFORE the 150ms peekInitialPayload wait so
	// server-first protocols (IMAP/POP3/SMTP) on blocked ports never stall 150ms.
	// Do NOT evaluate ban_private_ip before peeking, so Clash Fake-IP / GFW-poisoned
	// literal IPs with valid TLS SNI / HTTP Host still get rewritten by domain_sniff!
	aclEng := s.aclEng.Load()
	if aclEng.IsPortForbidden(destPort) {
		logger.Debugf("blocked user=%d dest=%s:%d rule=forbidden-port", user.ID, destHost, destPort)
		if onDial != nil {
			onDial(errors.New("blocked by audit policy"))
		}
		return
	}

	var peeked []byte
	if len(preread) > 0 {
		peeked = preread
	} else if onDial == nil {
		var perr error
		peeked, perr = s.peekInitialPayload(clientConn)
		if perr != nil {
			return
		}
	}

	sn := sniff.Inspect(peeked)
	effectiveHost := s.resolveEffectiveHost(aclEng, destHost, sn.Domain)
	route := aclEng.DecideForNode(s.cfg.NodeID, effectiveHost, destPort, sn.Domain, sn.Protocol)
	if route.Action == acl.ActionBlock {
		logger.Debugf("blocked user=%d dest=%s:%d effective=%s sni=%s proto=%s rule=%s", user.ID, destHost, destPort, effectiveHost, sn.Domain, sn.Protocol, route.RuleName)
		if onDial != nil {
			onDial(errors.New("blocked by audit policy"))
		}
		return
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
	return parseSOCKS5AddrWithAtyp(r, atyp[0])
}

func parseSOCKS5AddrWithAtyp(r io.Reader, atyp byte) (host string, port uint16, err error) {
	switch atyp {
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
		return "", 0, fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
	return host, port, nil
}
