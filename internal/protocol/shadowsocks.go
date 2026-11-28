package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/stats"
)

type ssCipherSpec struct {
	name     string
	keySize  int
	saltSize int
	is2022   bool
	makeAEAD func(subkey []byte) (cipher.AEAD, error)
}

func parseSSCipher(method string) (ssCipherSpec, error) {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return ssCipherSpec{name: m, keySize: 16, saltSize: 16, makeAEAD: newAESGCM}, nil
	case "aes-256-gcm", "aead_aes_256_gcm", "":
		return ssCipherSpec{name: "aes-256-gcm", keySize: 32, saltSize: 32, makeAEAD: newAESGCM}, nil
	case "chacha20-ietf-poly1305", "chacha20-poly1305", "aead_chacha20_poly1305":
		return ssCipherSpec{name: m, keySize: 32, saltSize: 32, makeAEAD: chacha20poly1305.New}, nil
	case "2022-blake3-aes-128-gcm":
		return ssCipherSpec{name: m, keySize: 16, saltSize: 16, is2022: true, makeAEAD: newAESGCM}, nil
	case "2022-blake3-aes-256-gcm":
		return ssCipherSpec{name: m, keySize: 32, saltSize: 32, is2022: true, makeAEAD: newAESGCM}, nil
	default:
		return ssCipherSpec{}, fmt.Errorf("unsupported shadowsocks cipher %q", method)
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func deriveSSSubkey(cs ssCipherSpec, masterKey, salt, dst []byte) {
	if cs.is2022 {
		var mat [64]byte
		n := copy(mat[:], masterKey)
		n += copy(mat[n:], salt)
		blake3DeriveKey("shadowsocks 2022 session subkey", mat[:n], dst[:cs.keySize])
		return
	}
	r := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))
	_, _ = io.ReadFull(r, dst[:cs.keySize])
}

func (s *Server) handleShadowsocksTCP(conn net.Conn) {
	if s.ssSpec.is2022 {
		s.handleSS2022TCP(conn)
		return
	}
	s.handleSSClassicAEADTCP(conn)
}

// handleSSClassicAEADTCP handles standard AEAD Shadowsocks (AES-128/256-GCM, ChaCha20-Poly1305).
func (s *Server) handleSSClassicAEADTCP(conn net.Conn) {
	cs := s.ssSpec
	var salt [32]byte
	if _, err := io.ReadFull(conn, salt[:cs.saltSize]); err != nil {
		return
	}
	var firstLenEnc [18]byte // 2-byte big-endian length + 16-byte AEAD tag
	if _, err := io.ReadFull(conn, firstLenEnc[:]); err != nil {
		return
	}

	idx := s.userIdx.Load()
	if idx == nil || len(idx.SSUsers) == 0 {
		return
	}

	var matchedUser *stats.UserEntry
	var matchedKey []byte
	var decAead cipher.AEAD
	var firstChunkLen int
	var subkey [32]byte
	var zeroNonce [12]byte
	var plainLen [2]byte

	clientIP := relay.ExtractClientIP(conn.RemoteAddr())
	if hintIdx, ok := s.ipHints.Lookup(clientIP); ok && hintIdx < len(idx.SSUsers) {
		u := &idx.SSUsers[hintIdx]
		deriveSSSubkey(cs, u.MasterKey, salt[:cs.saltSize], subkey[:cs.keySize])
		if aead, err := cs.makeAEAD(subkey[:cs.keySize]); err == nil {
			if _, err := aead.Open(plainLen[:0], zeroNonce[:], firstLenEnc[:], nil); err == nil {
				matchedUser = u.User
				matchedKey = u.MasterKey
				decAead = aead
				firstChunkLen = int(binary.BigEndian.Uint16(plainLen[:]) & 0x3FFF)
			}
		}
	}

	if matchedUser == nil {
		for i := range idx.SSUsers {
			u := &idx.SSUsers[i]
			deriveSSSubkey(cs, u.MasterKey, salt[:cs.saltSize], subkey[:cs.keySize])
			aead, err := cs.makeAEAD(subkey[:cs.keySize])
			if err != nil {
				continue
			}
			if _, err := aead.Open(plainLen[:0], zeroNonce[:], firstLenEnc[:], nil); err == nil {
				matchedUser = u.User
				matchedKey = u.MasterKey
				decAead = aead
				firstChunkLen = int(binary.BigEndian.Uint16(plainLen[:]) & 0x3FFF)
				s.ipHints.Store(clientIP, i)
				break
			}
		}
	}
	if matchedUser == nil || firstChunkLen <= 0 || firstChunkLen > 0x3FFF {
		return
	}
	if s.replay.CheckAndMark(salt[:cs.saltSize]) {
		return
	}

	// Read first encrypted payload chunk (nonce = 1)
	bp := bufpool.Get(bufpool.LargeSize)
	encChunk := (*bp)[:firstChunkLen+16]
	if _, err := io.ReadFull(conn, encChunk); err != nil {
		bufpool.Put(bp)
		return
	}
	var nonce1 [12]byte
	nonce1[0] = 1
	firstPayload, err := decAead.Open(encChunk[:0], nonce1[:], encChunk, nil)
	if err != nil {
		bufpool.Put(bp)
		return
	}

	pr := bytes.NewReader(firstPayload)
	destHost, destPort, err := parseSOCKS5Addr(pr)
	if err != nil {
		bufpool.Put(bp)
		return
	}
	var initialData []byte
	if pr.Len() > 0 {
		initialData = make([]byte, pr.Len())
		_, _ = pr.Read(initialData)
	}
	bufpool.Put(bp)
	_ = conn.SetDeadline(time.Time{})

	ssConn := &ssAEADStreamConn{
		Conn:      conn,
		cs:        cs,
		masterKey: matchedKey,
		readAEAD:  decAead,
		readNonce: [12]byte{2}, // nonce 0 used for len, nonce 1 used for payload -> next is 2
	}
	defer ssConn.releasePendingBuf()
	s.connectAndRelay(ssConn, matchedUser, destHost, destPort, initialData)
}

// handleSS2022TCP handles `2022-blake3-aes-128-gcm` & `2022-blake3-aes-256-gcm` including
// V2Board / Xboard Multi-User EIH (`server_key` + user identity header).
func (s *Server) handleSS2022TCP(conn net.Conn) {
	cs := s.ssSpec
	var reqSalt [32]byte
	if _, err := io.ReadFull(conn, reqSalt[:cs.saltSize]); err != nil {
		return
	}

	idx := s.userIdx.Load()
	if idx == nil || len(idx.SSUsers) == 0 {
		return
	}

	var matchedUser *stats.UserEntry
	var sessionKey []byte
	var decAEAD cipher.AEAD

	if len(s.ssPSK) > 0 && s.ssPSKBlk != nil {
		// Multi-User EIH mode: read 16-byte EIH block encrypted with AES-ECB(BLAKE3("shadowsocks 2022 identity subkey", iPSK || salt))
		var eihEnc [16]byte
		if _, err := io.ReadFull(conn, eihEnc[:]); err != nil {
			return
		}
		var mat [64]byte
		n := copy(mat[:], s.ssPSK)
		n += copy(mat[n:], reqSalt[:cs.saltSize])
		var idSubkey [32]byte
		blake3DeriveKey("shadowsocks 2022 identity subkey", mat[:n], idSubkey[:cs.keySize])
		idBlk, err := aes.NewCipher(idSubkey[:cs.keySize])
		if err != nil {
			return
		}
		var eihPlain [16]byte
		idBlk.Decrypt(eihPlain[:], eihEnc[:])
		entry, ok := idx.SSEIHMap[eihPlain]
		if !ok {
			return
		}
		matchedUser = entry.User
		sessionKey = entry.MasterKey

		var subkey [32]byte
		deriveSSSubkey(cs, sessionKey, reqSalt[:cs.saltSize], subkey[:cs.keySize])
		decAEAD, err = cs.makeAEAD(subkey[:cs.keySize])
		if err != nil {
			return
		}
	}

	// Fixed-length request header: 11 bytes plaintext + 16 bytes tag = 27 bytes
	var fixedEnc [27]byte
	if _, err := io.ReadFull(conn, fixedEnc[:]); err != nil {
		return
	}
	var zeroNonce [12]byte
	var fixedPlain [11]byte

	if decAEAD != nil {
		if _, err := decAEAD.Open(fixedPlain[:0], zeroNonce[:], fixedEnc[:], nil); err != nil {
			return
		}
	} else {
		var subkey [32]byte
		for i := range idx.SSUsers {
			u := &idx.SSUsers[i]
			deriveSSSubkey(cs, u.MasterKey, reqSalt[:cs.saltSize], subkey[:cs.keySize])
			aead, err := cs.makeAEAD(subkey[:cs.keySize])
			if err != nil {
				continue
			}
			if _, err := aead.Open(fixedPlain[:0], zeroNonce[:], fixedEnc[:], nil); err == nil {
				matchedUser = u.User
				sessionKey = u.MasterKey
				decAEAD = aead
				break
			}
		}
		if matchedUser == nil {
			return
		}
	}

	// Verify SS2022 header type == 0 (client stream) and timestamp within +-30 seconds
	if fixedPlain[0] != 0x00 {
		return
	}
	ts := int64(binary.BigEndian.Uint64(fixedPlain[1:9]))
	if math.Abs(float64(time.Now().Unix()-ts)) > 30 {
		return
	}
	if s.replay.CheckAndMark(reqSalt[:cs.saltSize]) {
		return
	}
	varHdrLen := int(binary.BigEndian.Uint16(fixedPlain[9:11]))
	if varHdrLen <= 0 || varHdrLen > 0xFFFF {
		return
	}

	bp := bufpool.Get(varHdrLen + 16)
	varEnc := (*bp)[:varHdrLen+16]
	if _, err := io.ReadFull(conn, varEnc); err != nil {
		bufpool.Put(bp)
		return
	}
	var nonce1 [12]byte
	nonce1[0] = 1
	varPlain, err := decAEAD.Open(varEnc[:0], nonce1[:], varEnc, nil)
	if err != nil {
		bufpool.Put(bp)
		return
	}

	pr := bytes.NewReader(varPlain)
	destHost, destPort, err := parseSOCKS5Addr(pr)
	if err != nil || pr.Len() < 2 {
		bufpool.Put(bp)
		return
	}
	var padLenBuf [2]byte
	_, _ = io.ReadFull(pr, padLenBuf[:])
	padLen := int(binary.BigEndian.Uint16(padLenBuf[:]))
	if pr.Len() < padLen {
		bufpool.Put(bp)
		return
	}
	if padLen > 0 {
		_, _ = pr.Seek(int64(padLen), io.SeekCurrent)
	}
	var initialData []byte
	if pr.Len() > 0 {
		initialData = make([]byte, pr.Len())
		_, _ = pr.Read(initialData)
	}
	bufpool.Put(bp)
	_ = conn.SetDeadline(time.Time{})

	reqSaltCopy := make([]byte, cs.saltSize)
	copy(reqSaltCopy, reqSalt[:cs.saltSize])

	ssConn := &ssAEADStreamConn{
		Conn:      conn,
		cs:        cs,
		masterKey: sessionKey,
		is2022:    true,
		reqSalt:   reqSaltCopy,
		readAEAD:  decAEAD,
		readNonce: [12]byte{2},
	}
	defer ssConn.releasePendingBuf()
	s.connectAndRelay(ssConn, matchedUser, destHost, destPort, initialData)
}

type ssAEADStreamConn struct {
	net.Conn
	cs        ssCipherSpec
	masterKey []byte
	is2022    bool
	reqSalt   []byte

	readMu          sync.Mutex
	readAEAD        cipher.AEAD
	readNonce       [12]byte
	leftover        []byte
	lenHdrBuf       [18]byte // preserves partial 18-byte length header across timeouts
	lenHdrRead      int      // bytes of lenHdrBuf already read
	pendingBodyBuf  *[]byte  // preserves partial chunk body across short timeouts (e.g. 150ms SNI peek)
	pendingBodySize int
	pendingBodyRead int

	writeMu    sync.Mutex
	writeAEAD  cipher.AEAD
	writeNonce [12]byte
}

func (c *ssAEADStreamConn) releasePendingBuf() {
	c.readMu.Lock()
	if c.pendingBodyBuf != nil {
		bufpool.Put(c.pendingBodyBuf)
		c.pendingBodyBuf = nil
		c.pendingBodySize = 0
		c.pendingBodyRead = 0
	}
	c.readMu.Unlock()
}

func (c *ssAEADStreamConn) Close() error {
	err := c.Conn.Close()
	c.releasePendingBuf()
	return err
}

func (c *ssAEADStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}

	// Preserve both the 18-byte length header AND partial chunk body across short timeouts
	// (e.g. 150ms SNI peek) without overwriting caller-set deadlines.
	if c.pendingBodyBuf == nil {
		for c.lenHdrRead < 18 {
			n, err := c.Conn.Read(c.lenHdrBuf[c.lenHdrRead:18])
			c.lenHdrRead += n
			if err != nil {
				return 0, err
			}
		}
		c.lenHdrRead = 0 // reset for next chunk
		var lenPlain [2]byte
		if _, err := c.readAEAD.Open(lenPlain[:0], c.readNonce[:], c.lenHdrBuf[:], nil); err != nil {
			return 0, err
		}
		incNonce(&c.readNonce)

		chunkLen := int(binary.BigEndian.Uint16(lenPlain[:]))
		if !c.is2022 {
			chunkLen &= 0x3FFF
		}
		if chunkLen == 0 {
			return 0, io.EOF
		}

		c.pendingBodyBuf = bufpool.Get(chunkLen + 16)
		c.pendingBodySize = chunkLen + 16
		c.pendingBodyRead = 0
	}

	enc := (*c.pendingBodyBuf)[:c.pendingBodySize]
	for c.pendingBodyRead < c.pendingBodySize {
		n, err := c.Conn.Read(enc[c.pendingBodyRead:c.pendingBodySize])
		c.pendingBodyRead += n
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, err
			}
			bufpool.Put(c.pendingBodyBuf)
			c.pendingBodyBuf = nil
			c.pendingBodySize = 0
			c.pendingBodyRead = 0
			return 0, err
		}
	}

	bp := c.pendingBodyBuf
	c.pendingBodyBuf = nil
	c.pendingBodySize = 0
	c.pendingBodyRead = 0
	defer bufpool.Put(bp)

	plain, err := c.readAEAD.Open(enc[:0], c.readNonce[:], enc, nil)
	if err != nil {
		return 0, err
	}
	incNonce(&c.readNonce)

	n := copy(p, plain)
	if n < len(plain) {
		c.leftover = append(c.leftover[:0], plain[n:]...)
	}
	return n, nil
}

func (c *ssAEADStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	maxChunk := 0x3FFF
	if c.is2022 {
		maxChunk = 0xFFFF
	}

	totalWritten := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = p[:maxChunk]
		}
		p = p[len(chunk):]

		if c.writeAEAD == nil {
			var srvSalt [32]byte
			if _, err := rand.Read(srvSalt[:c.cs.saltSize]); err != nil {
				return totalWritten, err
			}
			var subkey [32]byte
			deriveSSSubkey(c.cs, c.masterKey, srvSalt[:c.cs.saltSize], subkey[:c.cs.keySize])
			aead, err := c.cs.makeAEAD(subkey[:c.cs.keySize])
			if err != nil {
				return totalWritten, err
			}
			if c.is2022 {
				// SS2022 response: ServerSalt + AEAD(Type=1 | TS(8) | ReqSalt | uint16(len(chunk))) + AEAD(chunk)
				hdrPlain := make([]byte, 1+8+len(c.reqSalt)+2)
				hdrPlain[0] = 0x01
				binary.BigEndian.PutUint64(hdrPlain[1:9], uint64(time.Now().Unix()))
				copy(hdrPlain[9:], c.reqSalt)
				binary.BigEndian.PutUint16(hdrPlain[9+len(c.reqSalt):], uint16(len(chunk)))

				var initNonce [12]byte
				out := make([]byte, 0, c.cs.saltSize+len(hdrPlain)+16+len(chunk)+16)
				out = append(out, srvSalt[:c.cs.saltSize]...)
				out = aead.Seal(out, initNonce[:], hdrPlain, nil)
				incNonce(&initNonce)
				out = aead.Seal(out, initNonce[:], chunk, nil)
				incNonce(&initNonce)

				if _, err := c.Conn.Write(out); err != nil {
					return totalWritten, err
				}
				c.writeAEAD = aead
				c.writeNonce = initNonce
				totalWritten += len(chunk)
				continue
			}

			if _, err := c.Conn.Write(srvSalt[:c.cs.saltSize]); err != nil {
				return totalWritten, err
			}
			c.writeAEAD = aead
		}

		bp := bufpool.Get(2 + 16 + len(chunk) + 16)
		out := (*bp)[:0]
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(chunk)))
		out = c.writeAEAD.Seal(out, c.writeNonce[:], lb[:], nil)
		incNonce(&c.writeNonce)
		out = c.writeAEAD.Seal(out, c.writeNonce[:], chunk, nil)
		incNonce(&c.writeNonce)

		_, err := c.Conn.Write(out)
		bufpool.Put(bp)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += len(chunk)
	}
	return totalWritten, nil
}

func incNonce(n *[12]byte) {
	for i := 0; i < 12; i++ {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

type ssUDPSession struct {
	natConn   net.PacketConn
	user      *stats.UserEntry
	sessID    uint64
	masterKey []byte
	lastSeen  atomic.Int64
}

type ssUDPKey struct {
	clientAddr string
	routeKey   string
}

func (s *Server) serveShadowsocksUDP(pc net.PacketConn) {
	defer s.wg.Done()
	cs := s.ssSpec
	if cs.is2022 {
		// Classic UDP relay handles AEAD ciphers; SS2022 UDP skipped cleanly if unused
		return
	}

	var natMu sync.Mutex
	sessions := make(map[ssUDPKey]*ssUDPSession)
	asyncSem := make(chan struct{}, 32)

	defer func() {
		natMu.Lock()
		for _, sess := range sessions {
			_ = sess.natConn.Close()
		}
		sessions = nil
		natMu.Unlock()
	}()

	bp := bufpool.Get(bufpool.MaxUDPSize)
	buf := *bp
	defer bufpool.Put(bp)

	var zeroNonce [12]byte

	dispatchUDP := func(clientAddr net.Addr, clientIP netip.Addr, matchedUser *stats.UserEntry, matchedKey []byte, host string, port uint16, payload []byte) {
		route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, host, port, "", "")
		if route.Action == acl.ActionBlock {
			return
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
		dstUDP, err := relay.ResolveUDPTargetForRoute(rctx, host, port, route, s.dnsRes)
		if err != nil {
			rcancel()
			return
		}
		isIPv6 := dstUDP.IP.To4() == nil
		key := ssUDPKey{clientAddr: clientAddr.String(), routeKey: udpRouteKey(route, isIPv6)}

		natMu.Lock()
		if sessions == nil {
			natMu.Unlock()
			rcancel()
			return
		}
		sess, exists := sessions[key]
		// Prevent CGNAT / credential-rotation session hijacking across different users!
		if exists && (sess.user != matchedUser || !bytes.Equal(sess.masterKey, matchedKey)) {
			delete(sessions, key)
			_ = sess.natConn.Close()
			exists = false
			sess = nil
		}
		if exists {
			sess.lastSeen.Store(time.Now().Unix())
			natMu.Unlock()
			rcancel()
		} else {
			if len(sessions) >= 2048 {
				natMu.Unlock()
				rcancel()
				return
			}
			natMu.Unlock()

			// Dial UDP outbound and acquire Redis-backed UDP session OUTSIDE natMu so
			// slow SOCKS5 dials or Redis latency never stall other Shadowsocks UDP users.
			natPC, lerr := relay.DialUDPForRoute(rctx, route, isIPv6, s.dnsRes)
			rcancel()
			if lerr != nil {
				return
			}
			sessID, aerr := matchedUser.AcquireUDPSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), natPC)
			if aerr != nil {
				_ = natPC.Close()
				return
			}

			natMu.Lock()
			if sessions == nil {
				natMu.Unlock()
				_ = natPC.Close()
				matchedUser.ReleaseUDPSession(sessID)
				return
			}
			if existing, ok := sessions[key]; ok && existing.user == matchedUser && bytes.Equal(existing.masterKey, matchedKey) {
				existing.lastSeen.Store(time.Now().Unix())
				sess = existing
				natMu.Unlock()
				_ = natPC.Close()
				matchedUser.ReleaseUDPSession(sessID)
			} else {
				if existing != nil {
					delete(sessions, key)
					_ = existing.natConn.Close()
				}
				sess = &ssUDPSession{
					natConn:   natPC,
					user:      matchedUser,
					sessID:    sessID,
					masterKey: matchedKey,
				}
				sess.lastSeen.Store(time.Now().Unix())
				sessions[key] = sess
				natMu.Unlock()
				go s.pipeSSUDPReply(pc, clientAddr, sess, &natMu, sessions, key)
			}
		}

		if ul := matchedUser.EffectiveLimiter(); ul != nil {
			ul.Wait(len(payload))
		}
		s.tracker.NodeLimiter.Wait(len(payload))
		matchedUser.AddUpload(int64(len(payload)))
		if matchedUser.IsDisabled() {
			return
		}
		_, _ = sess.natConn.WriteTo(payload, dstUDP)
	}

	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n <= cs.saltSize+16+4 {
			continue
		}
		salt := buf[:cs.saltSize]
		ct := buf[cs.saltSize:n]

		idx := s.userIdx.Load()
		if idx == nil {
			continue
		}

		var matchedUser *stats.UserEntry
		var matchedKey []byte
		var plain []byte
		var subkey [32]byte
		plainBuf := make([]byte, len(ct))

		clientIP := relay.ExtractClientIP(clientAddr)
		if hintIdx, ok := s.ipHints.Lookup(clientIP); ok && hintIdx < len(idx.SSUsers) {
			u := &idx.SSUsers[hintIdx]
			deriveSSSubkey(cs, u.MasterKey, salt, subkey[:cs.keySize])
			if aead, err := cs.makeAEAD(subkey[:cs.keySize]); err == nil {
				if dec, err := aead.Open(plainBuf[:0], zeroNonce[:], ct, nil); err == nil {
					matchedUser = u.User
					matchedKey = u.MasterKey
					plain = dec
				}
			}
		}

		if matchedUser == nil {
			for i := range idx.SSUsers {
				u := &idx.SSUsers[i]
				deriveSSSubkey(cs, u.MasterKey, salt, subkey[:cs.keySize])
				aead, err := cs.makeAEAD(subkey[:cs.keySize])
				if err != nil {
					continue
				}
				if dec, err := aead.Open(plainBuf[:0], zeroNonce[:], ct, nil); err == nil {
					matchedUser = u.User
					matchedKey = u.MasterKey
					plain = dec
					s.ipHints.Store(clientIP, i)
					break
				}
			}
		}
		if matchedUser == nil || matchedUser.IsDisabled() {
			continue
		}
		// Reject replayed Shadowsocks UDP packets so attackers cannot amplify traffic or drain user quota!
		if s.replay.CheckAndMark(salt) {
			continue
		}

		pr := bytes.NewReader(plain)
		host, port, err := parseSOCKS5Addr(pr)
		if err != nil || pr.Len() == 0 {
			continue
		}
		payload := plain[len(plain)-pr.Len():]

		// Fast inline path when destination is already an IP literal and matching NAT session exists;
		// offload domain resolution / new session setup to bounded worker pool so slow DNS never stalls other users!
		if ipAddr, isIP := netip.ParseAddr(host); isIP == nil && matchedUser.EffectiveLimiter() == nil && s.tracker.NodeLimiter.IsUnlimited() {
			fastRoute := s.aclEng.Load().DecideForNode(s.cfg.NodeID, host, port, "", "")
			if fastRoute.Action == acl.ActionBlock {
				continue
			}
			fastKey := ssUDPKey{clientAddr: clientAddr.String(), routeKey: udpRouteKey(fastRoute, ipAddr.Unmap().Is6())}
			natMu.Lock()
			_, hasSess := sessions[fastKey]
			natMu.Unlock()
			if hasSess {
				dispatchUDP(clientAddr, clientIP, matchedUser, matchedKey, host, port, payload)
				continue
			}
		}

		payCopy := make([]byte, len(payload))
		copy(payCopy, payload)
		select {
		case asyncSem <- struct{}{}:
			go func(ca net.Addr, cip netip.Addr, u *stats.UserEntry, mk []byte, h string, p uint16, data []byte) {
				defer func() { <-asyncSem }()
				dispatchUDP(ca, cip, u, mk, h, p, data)
			}(clientAddr, clientIP, matchedUser, matchedKey, host, port, payCopy)
		default:
		}
	}
}

func (s *Server) pipeSSUDPReply(
	mainPC net.PacketConn,
	clientAddr net.Addr,
	sess *ssUDPSession,
	natMu *sync.Mutex,
	sessions map[ssUDPKey]*ssUDPSession,
	key ssUDPKey,
) {
	defer func() {
		_ = sess.natConn.Close()
		if sess.user != nil {
			sess.user.ReleaseUDPSession(sess.sessID)
		}
		natMu.Lock()
		if sessions != nil && sessions[key] == sess {
			delete(sessions, key)
		}
		natMu.Unlock()
	}()

	idle := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if idle < 10*time.Second {
		idle = 60 * time.Second
	}
	cs := s.ssSpec
	var zeroNonce [12]byte

	for {
		if sess.user.IsDisabled() {
			return
		}
		_ = sess.natConn.SetReadDeadline(time.Now().Add(idle))
		n, raddr, rbuf, bp, err := relay.ReadPacketZeroIdle(sess.natConn)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(sess.lastSeen.Load(), 0)) < idle {
				continue
			}
			return
		}
		ua, ok := raddr.(*net.UDPAddr)
		if !ok {
			bufpool.Put(bp)
			continue
		}
		sess.lastSeen.Store(time.Now().Unix())
		if ul := sess.user.EffectiveLimiter(); ul != nil {
			ul.Wait(n)
		}
		s.tracker.NodeLimiter.Wait(n)
		sess.user.AddDownload(int64(n))

		// Build SOCKS5Addr + payload (guard nil IP from unexpected raddr types)
		if ua.IP == nil {
			bufpool.Put(bp)
			continue
		}
		ip4 := ua.IP.To4()
		plain := make([]byte, 0, 22+n)
		if ip4 != nil {
			plain = append(plain, 0x01)
			plain = append(plain, ip4...)
		} else {
			plain = append(plain, 0x04)
			plain = append(plain, ua.IP.To16()...)
		}
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], uint16(ua.Port))
		plain = append(plain, pb[:]...)
		plain = append(plain, rbuf[:n]...)
		bufpool.Put(bp)

		out := make([]byte, cs.saltSize, cs.saltSize+len(plain)+16)
		_, _ = rand.Read(out[:cs.saltSize])
		var subkey [32]byte
		deriveSSSubkey(cs, sess.masterKey, out[:cs.saltSize], subkey[:cs.keySize])
		aead, err := cs.makeAEAD(subkey[:cs.keySize])
		if err != nil {
			return
		}
		out = aead.Seal(out, zeroNonce[:], plain, nil)
		_, _ = mainPC.WriteTo(out, clientAddr)
	}
}

var _ = errors.New
