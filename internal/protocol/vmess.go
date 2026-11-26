package protocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/relay"
	"github.com/xmg665/xoga/internal/stats"
)

const vmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

var (
	kdfBaseIpad [64]byte
	kdfBaseOpad [64]byte

	kdfSaltAuthID    = []byte("AES Auth ID Encryption")
	kdfSaltHdrLenKey = []byte("VMess Header AEAD Key_Length")
	kdfSaltHdrLenIV  = []byte("VMess Header AEAD Nonce_Length")
	kdfSaltHdrKey    = []byte("VMess Header AEAD Key")
	kdfSaltHdrIV     = []byte("VMess Header AEAD Nonce")
	kdfSaltRespLenK  = []byte("AEAD Resp Header Len Key")
	kdfSaltRespLenIV = []byte("AEAD Resp Header Len IV")
	kdfSaltRespKey   = []byte("AEAD Resp Header Key")
	kdfSaltRespIV    = []byte("AEAD Resp Header IV")
)

func init() {
	const baseSalt = "VMess AEAD KDF"
	for i := 0; i < 64; i++ {
		kdfBaseIpad[i] = 0x36
		kdfBaseOpad[i] = 0x5c
	}
	for i := 0; i < len(baseSalt); i++ {
		kdfBaseIpad[i] ^= baseSalt[i]
		kdfBaseOpad[i] ^= baseSalt[i]
	}
}

func vmessCmdKey(uuid [16]byte) [16]byte {
	h := md5.New()
	h.Write(uuid[:])
	h.Write([]byte(vmessMagic))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func fillHMACPads(k []byte, ipad, opad *[64]byte) {
	for i := 0; i < 64; i++ {
		ipad[i] = 0x36
		opad[i] = 0x5c
	}
	for i := 0; i < len(k); i++ {
		ipad[i] ^= k[i]
		opad[i] ^= k[i]
	}
}

func hmacStep0(msg []byte) [32]byte {
	var inBuf [320]byte
	var inSlice []byte
	if 64+len(msg) <= len(inBuf) {
		copy(inBuf[0:64], kdfBaseIpad[:])
		copy(inBuf[64:], msg)
		inSlice = inBuf[:64+len(msg)]
	} else {
		inSlice = make([]byte, 64+len(msg))
		copy(inSlice[0:64], kdfBaseIpad[:])
		copy(inSlice[64:], msg)
	}
	inner := sha256.Sum256(inSlice)
	var outBuf [96]byte
	copy(outBuf[0:64], kdfBaseOpad[:])
	copy(outBuf[64:96], inner[:])
	return sha256.Sum256(outBuf[:])
}

func hmacStep1(p1, msg []byte) [32]byte {
	var k1 [32]byte
	if len(p1) > 64 {
		k1 = hmacStep0(p1)
		p1 = k1[:]
	}
	var ipad, opad [64]byte
	fillHMACPads(p1, &ipad, &opad)

	var inBuf [320]byte
	copy(inBuf[0:64], ipad[:])
	copy(inBuf[64:], msg)
	inner := hmacStep0(inBuf[:64+len(msg)])

	var outBuf [96]byte
	copy(outBuf[0:64], opad[:])
	copy(outBuf[64:96], inner[:])
	return hmacStep0(outBuf[:])
}

func hmacStep2(p1, p2, msg []byte) [32]byte {
	var k2 [32]byte
	if len(p2) > 64 {
		k2 = hmacStep1(p1, p2)
		p2 = k2[:]
	}
	var ipad, opad [64]byte
	fillHMACPads(p2, &ipad, &opad)

	var inBuf [256]byte
	copy(inBuf[0:64], ipad[:])
	copy(inBuf[64:], msg)
	inner := hmacStep1(p1, inBuf[:64+len(msg)])

	var outBuf [96]byte
	copy(outBuf[0:64], opad[:])
	copy(outBuf[64:96], inner[:])
	return hmacStep1(p1, outBuf[:])
}

// vmessKDF1 computes 1-level VMess AEAD KDF (`HMAC(HMAC(SHA256, "VMess AEAD KDF"), p1)(key)`) with 0 heap allocations.
func vmessKDF1(key, p1 []byte) [32]byte {
	return hmacStep1(p1, key)
}

// vmessKDF3 computes 3-level VMess AEAD KDF (`p1`, `authID`, `nonce`) on stack arrays with 0 heap allocations.
func vmessKDF3(key, p1, p2, p3 []byte) [32]byte {
	var k3 [32]byte
	if len(p3) > 64 {
		k3 = hmacStep2(p1, p2, p3)
		p3 = k3[:]
	}
	var ipad, opad [64]byte
	fillHMACPads(p3, &ipad, &opad)

	var inBuf [128]byte
	copy(inBuf[0:64], ipad[:])
	copy(inBuf[64:], key)
	inner := hmacStep2(p1, p2, inBuf[:64+len(key)])

	var outBuf [96]byte
	copy(outBuf[0:64], opad[:])
	copy(outBuf[64:96], inner[:])
	return hmacStep2(p1, p2, outBuf[:])
}

// vmessKDF derives keys per V2Ray/Xray VMess AEAD specification (`HMAC-SHA256` nested KDF).
func vmessKDF(key []byte, path ...string) []byte {
	if len(path) == 1 && len(key) <= 64 {
		sum := vmessKDF1(key, []byte(path[0]))
		return sum[:]
	}
	if len(path) == 3 && len(key) <= 64 {
		sum := vmessKDF3(key, []byte(path[0]), []byte(path[1]), []byte(path[2]))
		return sum[:]
	}
	creator := func() hash.Hash {
		return hmac.New(sha256.New, []byte("VMess AEAD KDF"))
	}
	for _, p := range path {
		prev := creator
		localPath := []byte(p)
		creator = func() hash.Hash {
			return hmac.New(prev, localPath)
		}
	}
	h := creator()
	h.Write(key)
	return h.Sum(nil)
}

// checkVMessBlock validates a candidate user's AES-128 AuthID block.
// Checking the 64-bit Unix timestamp range (`[now-120, now+120]`) BEFORE CRC32 rejects
// 99.999999999999999% (`1 - 241/2^64`) of non-matching keys in a single CPU subtraction+compare,
// completely eliminating software CRC32 overhead during multi-thousand-user scans.
func checkVMessBlock(blk cipher.Block, authID, scratch []byte, minTS uint64) bool {
	blk.Decrypt(scratch, authID)
	if binary.BigEndian.Uint64(scratch[:8])-minTS > 240 {
		return false
	}
	return crc32.ChecksumIEEE(scratch[:12]) == binary.BigEndian.Uint32(scratch[12:16])
}

func checkVMessCandidate(cand *VMessUserEntry, authID, scratch []byte, now int64) bool {
	return checkVMessBlock(cand.AuthBlock, authID, scratch, uint64(now-120))
}

func fnv1a32(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// handleVMess isolates the stack-heavy AEAD KDF handshake into a `//go:noinline` helper so
// Go's stack shrinker reclaims the ~2.5 KiB handshake stack frame as soon as streaming begins.
func (s *Server) handleVMess(conn net.Conn) {
	vmConn, user, destHost, destPort, cmd, ok := s.handshakeVMess(conn)
	if !ok {
		return
	}
	defer vmConn.releaseReadBuf()
	if cmd == 0x03 || (cmd == 0x01 && strings.EqualFold(destHost, "v1.mux.cool")) {
		s.handleVLESSMux(vmConn, user, "")
		return
	}
	if cmd == 0x02 {
		s.handleVMessUDP(vmConn, user, destHost, destPort)
		return
	}
	s.connectAndRelay(vmConn, user, destHost, destPort, nil)
}

//go:noinline
func (s *Server) handshakeVMess(conn net.Conn) (*vmessStreamConn, *stats.UserEntry, string, uint16, byte, bool) {
	var br io.Reader = conn
	if _, alreadyBuf := conn.(interface{ IsBufferedStream() bool }); !alreadyBuf {
		br = bufio.NewReaderSize(conn, 2048)
	}

	var authID [16]byte
	if _, err := io.ReadFull(br, authID[:]); err != nil {
		return nil, nil, "", 0, 0, false
	}

	idx := s.userIdx.Load()
	if idx == nil || len(idx.VMessUsers) == 0 {
		return nil, nil, "", 0, 0, false
	}

	minTS := uint64(time.Now().Unix() - 120)
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())

	var scratchArr [16]byte
	scratch := scratchArr[:]
	authSlice := authID[:]
	blocks := idx.VMessBlocks

	// Bitset tracking tested user indices (up to 16,384 users in 2 KiB on short-lived handshake stack)
	// so fallback scan never double-decrypts candidates already checked via ipHints or hotRing.
	var tested [256]uint64
	markTested := func(uIdx int) {
		if uIdx >= 0 && uIdx < 256*64 {
			tested[uIdx>>6] |= uint64(1) << (uint(uIdx) & 63)
		}
	}
	wasTested := func(uIdx int) bool {
		if uIdx >= 0 && uIdx < 256*64 {
			return (tested[uIdx>>6] & (uint64(1) << (uint(uIdx) & 63))) != 0
		}
		return false
	}

	var matched *VMessUserEntry
	// 1. O(1) lock-free IP->User hint fast path (1 AES block decrypt when client IP is distinct)
	if h, ok := s.ipHints.Lookup(clientIP); ok && h < len(blocks) {
		markTested(h)
		if checkVMessBlock(blocks[h], authSlice, scratch, minTS) {
			matched = &idx.VMessUsers[h]
		}
	}
	// 2. L1-cached active hot-user ring (for L4 transit relays sharing 1 source IP across thousands of streams)
	if matched == nil {
		for slot := 0; slot < hotRingSize; slot++ {
			enc := int(s.hotRing.slots[slot].Load())
			if enc == 0 {
				break
			}
			uIdx := enc - 1
			if uIdx < 0 || uIdx >= len(blocks) || wasTested(uIdx) {
				continue
			}
			markTested(uIdx)
			if checkVMessBlock(blocks[uIdx], authSlice, scratch, minTS) {
				matched = &idx.VMessUsers[uIdx]
				s.ipHints.Store(clientIP, uIdx)
				break
			}
		}
	}
	// 3. Full fallback scan over compact cipher.Block slice only when a cold user connects
	if matched == nil {
		for i, blk := range blocks {
			if wasTested(i) {
				continue
			}
			if checkVMessBlock(blk, authSlice, scratch, minTS) {
				matched = &idx.VMessUsers[i]
				s.ipHints.Store(clientIP, i)
				s.hotRing.Promote(i)
				break
			}
		}
	}
	if matched == nil || matched.User.IsDisabled() {
		return nil, nil, "", 0, 0, false
	}

	// Reject replayed AuthIDs after authentication succeeds (prevents GFW active replay probing)
	if s.replay.CheckAndMark(authID[:]) {
		return nil, nil, "", 0, 0, false
	}

	// Read 18-byte encrypted header length + 8-byte connection nonce
	var encLenAndNonce [26]byte
	if _, err := io.ReadFull(br, encLenAndNonce[:]); err != nil {
		return nil, nil, "", 0, 0, false
	}
	encHdrLen := encLenAndNonce[:18]
	connNonce := encLenAndNonce[18:26]

	lenKey := vmessKDF3(matched.CmdKey[:], kdfSaltHdrLenKey, authID[:], connNonce)
	lenNonce := vmessKDF3(matched.CmdKey[:], kdfSaltHdrLenIV, authID[:], connNonce)
	lenBlk, err := aes.NewCipher(lenKey[:16])
	if err != nil {
		return nil, nil, "", 0, 0, false
	}
	lenGCM, err := cipher.NewGCM(lenBlk)
	if err != nil {
		return nil, nil, "", 0, 0, false
	}
	var hdrLenBytes [2]byte
	if _, err := lenGCM.Open(hdrLenBytes[:0], lenNonce[:12], encHdrLen, authID[:]); err != nil {
		return nil, nil, "", 0, 0, false
	}
	hdrLen := int(binary.BigEndian.Uint16(hdrLenBytes[:])) + 16
	if hdrLen <= 16 || hdrLen > 2048 {
		return nil, nil, "", 0, 0, false
	}

	var stackHdr [512]byte
	var encHdr []byte
	if hdrLen <= len(stackHdr) {
		encHdr = stackHdr[:hdrLen]
	} else {
		encHdr = make([]byte, hdrLen)
	}
	if _, err := io.ReadFull(br, encHdr); err != nil {
		return nil, nil, "", 0, 0, false
	}

	payKey := vmessKDF3(matched.CmdKey[:], kdfSaltHdrKey, authID[:], connNonce)
	payNonce := vmessKDF3(matched.CmdKey[:], kdfSaltHdrIV, authID[:], connNonce)
	payBlk, err := aes.NewCipher(payKey[:16])
	if err != nil {
		return nil, nil, "", 0, 0, false
	}
	payGCM, err := cipher.NewGCM(payBlk)
	if err != nil {
		return nil, nil, "", 0, 0, false
	}
	hdrPlain, err := payGCM.Open(encHdr[:0], payNonce[:12], encHdr, authID[:])
	if err != nil || len(hdrPlain) < 41 {
		return nil, nil, "", 0, 0, false
	}

	// Verify FNV1a32 checksum at end of VMess command header
	if fnv1a32(hdrPlain[:len(hdrPlain)-4]) != binary.BigEndian.Uint32(hdrPlain[len(hdrPlain)-4:]) || hdrPlain[0] != 0x01 {
		return nil, nil, "", 0, 0, false
	}

	var reqBodyIV, reqBodyKey [16]byte
	copy(reqBodyIV[:], hdrPlain[1:17])
	copy(reqBodyKey[:], hdrPlain[17:33])
	respV := hdrPlain[33]
	opt := hdrPlain[34]
	pLen := int(hdrPlain[35] >> 4)
	secType := hdrPlain[35] & 0x0F
	cmd := hdrPlain[37]

	var destPort uint16
	var destHost string
	switch cmd {
	case 0x01, 0x02:
		if len(hdrPlain)-4-pLen <= 40 {
			return nil, nil, "", 0, 0, false
		}
		destPort = binary.BigEndian.Uint16(hdrPlain[38:40])
		addrReader := bytes.NewReader(hdrPlain[40 : len(hdrPlain)-4-pLen])
		destHost, err = parseVLESSAddr(addrReader)
		if err != nil {
			return nil, nil, "", 0, 0, false
		}
	case 0x03: // RequestCommandMux (Mux.Cool without target address in VMess header)
		if len(hdrPlain)-4-pLen < 38 {
			return nil, nil, "", 0, 0, false
		}
	default:
		return nil, nil, "", 0, 0, false
	}
	_ = conn.SetDeadline(time.Time{})

	vmConn, err := newVMessStreamConn(conn, br, reqBodyKey, reqBodyIV, respV, opt, secType, cmd == 0x02)
	if err != nil {
		return nil, nil, "", 0, 0, false
	}
	return vmConn, matched.User, destHost, destPort, cmd, true
}

func (s *Server) handleVMessUDP(vmConn *vmessStreamConn, user *stats.UserEntry, destHost string, destPort uint16) {
	clientIP := relay.ExtractClientIP(vmConn.RemoteAddr())
	connID, err := user.AcquireSession(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter(), vmConn)
	if err != nil {
		return
	}
	defer user.ReleaseSession(connID)

	route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, destHost, destPort, "", "")
	if route.Action == acl.ActionBlock {
		return
	}

	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	udpAddr, err := relay.ResolveUDPTargetForRoute(rctx, destHost, destPort, route, s.dnsRes)
	if err != nil {
		rcancel()
		return
	}
	targetUDP, err := relay.DialUDPForRoute(rctx, route, udpAddr.IP.To4() == nil, s.dnsRes)
	rcancel()
	if err != nil {
		return
	}
	defer targetUDP.Close()

	idleDur := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	var lastActive atomic.Int64
	lastActive.Store(time.Now().Unix())

	done := make(chan struct{})
	go func() {
		defer close(done)
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		defer bufpool.Put(bp)
		for {
			_ = targetUDP.SetReadDeadline(time.Now().Add(idleDur))
			n, _, err := targetUDP.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
					continue
				}
				return
			}
			if n <= 0 || n > 65535-80 {
				continue
			}
			lastActive.Store(time.Now().Unix())
			if ul := user.EffectiveLimiter(); ul != nil {
				ul.Wait(n)
			}
			s.tracker.NodeLimiter.Wait(n)
			user.AddDownload(int64(n))

			_ = vmConn.SetWriteDeadline(time.Now().Add(idleDur))
			if _, werr := vmConn.writeSingleChunk(buf[:n]); werr != nil {
				return
			}
		}
	}()

	bp := bufpool.Get(bufpool.MaxUDPSize)
	inBuf := *bp
	defer bufpool.Put(bp)

	for {
		_ = vmConn.SetReadDeadline(time.Now().Add(idleDur))
		n, err := vmConn.readSingleChunk(inBuf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Since(time.Unix(lastActive.Load(), 0)) < idleDur {
				continue
			}
			break
		}
		if n == 0 {
			continue
		}
		lastActive.Store(time.Now().Unix())
		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(n)
		}
		s.tracker.NodeLimiter.Wait(n)
		user.AddUpload(int64(n))
		_, _ = targetUDP.WriteTo(inBuf[:n], udpAddr)
	}

	_ = targetUDP.Close()
	<-done
}

type wsPrependWriter interface {
	WritePrependWSFrame(buf []byte, payloadOffset int) error
}

type vmessStreamConn struct {
	net.Conn
	wsFast       wsPrependWriter
	reader       io.Reader
	respV        byte
	rawStream    bool
	optChunkMask bool
	optGlobalPad bool
	secType      byte

	reqKey  [16]byte
	reqIV   [16]byte
	respKey [16]byte
	respIV  [16]byte

	readMu         sync.Mutex
	readAEAD       cipher.AEAD
	readLegacyCFB  bool
	readMask       sha3.ShakeHash
	readCount      uint16
	hasPendingMask bool
	pendingPadLen  int
	pendingMask    uint16
	hdrBytes       [2]byte
	hdrRead        int
	readBuf        *[]byte // pooled buffer held ONLY while unread leftover bytes remain in current chunk
	leftover       []byte

	writeMu    sync.Mutex
	sentResp   bool
	sentEOF    bool
	writeAEAD  cipher.AEAD
	writeCFB   cipher.Stream
	writeMask  sha3.ShakeHash
	writeCount uint16
}

func newVMessStreamConn(c net.Conn, br io.Reader, reqKey, reqIV [16]byte, respV, opt, secType byte, isUDP bool) (*vmessStreamConn, error) {
	rk := sha256.Sum256(reqKey[:])
	riv := sha256.Sum256(reqIV[:])
	if br == nil {
		br = c
	}
	rawStream := !isUDP && (secType == 0x06 || (opt&0x01) == 0)
	chunkMask := !rawStream && (opt&0x04) != 0
	wsFast, _ := c.(wsPrependWriter)
	vc := &vmessStreamConn{
		Conn:         c,
		wsFast:       wsFast,
		reader:       br,
		respV:        respV,
		rawStream:    rawStream,
		optChunkMask: chunkMask,
		optGlobalPad: chunkMask && (opt&0x08) != 0,
		secType:      secType,
		reqKey:       reqKey,
		reqIV:        reqIV,
	}
	copy(vc.respKey[:], rk[:16])
	copy(vc.respIV[:], riv[:16])

	if vc.optChunkMask {
		rm := sha3.NewShake128()
		_, _ = rm.Write(reqIV[:])
		vc.readMask = rm

		wm := sha3.NewShake128()
		_, _ = wm.Write(vc.respIV[:])
		vc.writeMask = wm
	}

	if secType == 0x01 || secType == 0x02 { // Legacy AES-128-CFB + FNV1a32
		reqBlk, err := aes.NewCipher(reqKey[:])
		if err != nil {
			return nil, err
		}
		respBlk, err := aes.NewCipher(vc.respKey[:])
		if err != nil {
			return nil, err
		}
		vc.reader = &cipher.StreamReader{
			S: cipher.NewCFBDecrypter(reqBlk, reqIV[:]),
			R: br,
		}
		vc.readLegacyCFB = true
		vc.writeCFB = cipher.NewCFBEncrypter(respBlk, vc.respIV[:])
		return vc, nil
	}

	var err error
	vc.readAEAD, err = makeVMessBodyAEAD(secType, reqKey[:])
	if err != nil {
		return nil, err
	}
	vc.writeAEAD, err = makeVMessBodyAEAD(secType, vc.respKey[:])
	if err != nil {
		return nil, err
	}
	return vc, nil
}

func (v *vmessStreamConn) NetConn() net.Conn {
	return v.Conn
}

func makeVMessBodyAEAD(secType byte, key16 []byte) (cipher.AEAD, error) {
	switch secType {
	case 3: // AES-128-GCM
		blk, err := aes.NewCipher(key16)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case 4: // ChaCha20-Poly1305 (32-byte key = MD5(key16) || MD5(MD5(key16)))
		var k32 [32]byte
		m1 := md5.Sum(key16)
		m2 := md5.Sum(m1[:])
		copy(k32[0:16], m1[:])
		copy(k32[16:32], m2[:])
		return chacha20poly1305.New(k32[:])
	case 5, 6: // None (0x05) / Zero (0x06)
		return nil, nil
	default:
		return nil, errors.New("unsupported VMess security cipher")
	}
}

func (v *vmessStreamConn) nextMask(sh sha3.ShakeHash) uint16 {
	if sh == nil {
		return 0
	}
	var b [2]byte
	_, _ = sh.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func (v *vmessStreamConn) releaseReadBuf() {
	v.readMu.Lock()
	if v.readBuf != nil {
		bufpool.Put(v.readBuf)
		v.readBuf = nil
		v.leftover = nil
	}
	v.readMu.Unlock()
}

func (v *vmessStreamConn) FlushResponseHeader() error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	if !v.sentResp {
		v.sentResp = true
		if err := v.sendAEADResponseHeader(); err != nil {
			return err
		}
	}
	if !v.rawStream && !v.sentEOF {
		v.sentEOF = true
		_ = v.writeFramedLocked(nil)
	}
	return nil
}

func (v *vmessStreamConn) Close() error {
	v.releaseReadBuf()
	return v.Conn.Close()
}

func (v *vmessStreamConn) readSingleChunk(dst []byte) (int, error) {
	v.readMu.Lock()
	defer v.readMu.Unlock()

	if v.rawStream {
		return v.reader.Read(dst)
	}

	// Preserve Shake128 mask & partial 2-byte length progress across 150ms SNI peek timeouts!
	if !v.hasPendingMask {
		v.pendingPadLen = 0
		if v.optGlobalPad {
			v.pendingPadLen = int(v.nextMask(v.readMask) % 64)
		}
		v.pendingMask = v.nextMask(v.readMask)
		v.hasPendingMask = true
	}

	for v.hdrRead < 2 {
		n, err := v.reader.Read(v.hdrBytes[v.hdrRead:2])
		v.hdrRead += n
		if err != nil {
			return 0, err
		}
	}
	padLen := v.pendingPadLen
	sizeMask := v.pendingMask
	v.hdrRead = 0
	v.hasPendingMask = false

	size := int(binary.BigEndian.Uint16(v.hdrBytes[:]) ^ sizeMask)

	overhead := 0
	if v.readAEAD != nil {
		overhead = v.readAEAD.Overhead()
	} else if v.readLegacyCFB {
		overhead = 4
	}
	if size == overhead+padLen {
		if size > 0 {
			var eofBuf [128]byte
			if _, err := io.ReadFull(v.reader, eofBuf[:size]); err != nil {
				return 0, err
			}
			if v.readAEAD != nil {
				var nonce [12]byte
				binary.BigEndian.PutUint16(nonce[0:2], v.readCount)
				copy(nonce[2:12], v.reqIV[2:12])
				v.readCount++
				if _, err := v.readAEAD.Open(eofBuf[:0], nonce[:], eofBuf[:overhead], nil); err != nil {
					return 0, err
				}
			}
		}
		return 0, io.EOF
	}
	if size <= overhead+padLen || size > 65535 {
		return 0, io.EOF
	}

	bp := bufpool.Get(size)
	chunk := (*bp)[:size]
	if _, err := io.ReadFull(v.reader, chunk); err != nil {
		bufpool.Put(bp)
		return 0, err
	}
	encData := chunk[:size-padLen]

	plain := encData
	if v.readAEAD != nil {
		var nonce [12]byte
		binary.BigEndian.PutUint16(nonce[0:2], v.readCount)
		copy(nonce[2:12], v.reqIV[2:12])
		v.readCount++
		var err error
		plain, err = v.readAEAD.Open(encData[:0], nonce[:], encData, nil)
		if err != nil {
			bufpool.Put(bp)
			return 0, err
		}
	} else if v.readLegacyCFB {
		if binary.BigEndian.Uint32(encData[:4]) != fnv1a32(encData[4:]) {
			bufpool.Put(bp)
			return 0, errors.New("vmess cfb fnv1a mismatch")
		}
		plain = encData[4:]
	}
	n := copy(dst, plain)
	if n < len(plain) {
		if v.readBuf != nil {
			bufpool.Put(v.readBuf)
		}
		v.readBuf = bp
		v.leftover = plain[n:]
	} else {
		bufpool.Put(bp)
	}
	return n, nil
}

func (v *vmessStreamConn) Read(p []byte) (int, error) {
	v.readMu.Lock()
	if len(v.leftover) > 0 {
		n := copy(p, v.leftover)
		v.leftover = v.leftover[n:]
		if len(v.leftover) == 0 && v.readBuf != nil {
			bufpool.Put(v.readBuf)
			v.readBuf = nil
			v.leftover = nil
		}
		v.readMu.Unlock()
		return n, nil
	}
	v.readMu.Unlock()
	return v.readSingleChunk(p)
}

func (v *vmessStreamConn) writeSingleChunk(part []byte) (int, error) {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()

	if !v.sentResp {
		v.sentResp = true
		if err := v.sendAEADResponseHeader(); err != nil {
			return 0, err
		}
	}
	if err := v.writeFramedLocked(part); err != nil {
		return 0, err
	}
	return len(part), nil
}

func (v *vmessStreamConn) writeFramedLocked(part []byte) error {
	padLen := 0
	if v.optGlobalPad {
		padLen = int(v.nextMask(v.writeMask) % 64)
	}
	if len(part)+16+padLen > 65535 {
		return io.ErrShortBuffer
	}
	sizeMask := v.nextMask(v.writeMask)

	// Reserve 10 bytes of prefix headroom when backed by WebSocket so `wsConn.WritePrependWSFrame`
	// prepends the 2–10 byte RFC 6455 header in-place and emits 1 single contiguous `write(2)` syscall!
	const wsHeadroom = 10
	bp := bufpool.Get(wsHeadroom + 2 + len(part) + 16 + padLen)
	out := (*bp)[:wsHeadroom+2]
	if v.writeAEAD != nil {
		var nonce [12]byte
		binary.BigEndian.PutUint16(nonce[0:2], v.writeCount)
		copy(nonce[2:12], v.respIV[2:12])
		v.writeCount++
		out = v.writeAEAD.Seal(out, nonce[:], part, nil)
	} else if v.writeCFB != nil {
		var fnvBytes [4]byte
		binary.BigEndian.PutUint32(fnvBytes[:], fnv1a32(part))
		out = append(out, fnvBytes[:]...)
		out = append(out, part...)
	} else {
		out = append(out, part...)
	}
	if padLen > 0 {
		padStart := len(out)
		out = out[:padStart+padLen]
		_, _ = rand.Read(out[padStart:])
	}
	wireSize := uint16(len(out)-(wsHeadroom+2)) ^ sizeMask
	binary.BigEndian.PutUint16(out[wsHeadroom:wsHeadroom+2], wireSize)
	if v.writeCFB != nil {
		v.writeCFB.XORKeyStream(out[wsHeadroom:], out[wsHeadroom:])
	}
	var err error
	if v.wsFast != nil {
		err = v.wsFast.WritePrependWSFrame(out, wsHeadroom)
	} else {
		_, err = v.Conn.Write(out[wsHeadroom:])
	}
	bufpool.Put(bp)
	return err
}

func (v *vmessStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	v.writeMu.Lock()
	defer v.writeMu.Unlock()

	if !v.sentResp {
		v.sentResp = true
		if err := v.sendAEADResponseHeader(); err != nil {
			return 0, err
		}
	}
	if v.rawStream {
		if v.writeCFB != nil {
			bp := bufpool.Get(len(p))
			enc := (*bp)[:len(p)]
			v.writeCFB.XORKeyStream(enc, p)
			n, err := v.Conn.Write(enc)
			bufpool.Put(bp)
			return n, err
		}
		return v.Conn.Write(p)
	}

	total := 0
	const maxPlain = 16384 - 128
	for len(p) > 0 {
		part := p
		if len(part) > maxPlain {
			part = p[:maxPlain]
		}
		p = p[len(part):]

		if err := v.writeFramedLocked(part); err != nil {
			return total, err
		}
		total += len(part)
	}
	return total, nil
}

func (v *vmessStreamConn) sendAEADResponseHeader() error {
	respPlain := [4]byte{v.respV, 0x00, 0x00, 0x00}
	lenKey := vmessKDF1(v.respKey[:], kdfSaltRespLenK)
	lenNonce := vmessKDF1(v.respIV[:], kdfSaltRespLenIV)
	lenBlk, err := aes.NewCipher(lenKey[:16])
	if err != nil {
		return err
	}
	lenGCM, err := cipher.NewGCM(lenBlk)
	if err != nil {
		return err
	}
	var hdrLenPlain [2]byte
	binary.BigEndian.PutUint16(hdrLenPlain[:], 4)

	payKey := vmessKDF1(v.respKey[:], kdfSaltRespKey)
	payNonce := vmessKDF1(v.respIV[:], kdfSaltRespIV)
	payBlk, err := aes.NewCipher(payKey[:16])
	if err != nil {
		return err
	}
	payGCM, err := cipher.NewGCM(payBlk)
	if err != nil {
		return err
	}

	var out [38]byte
	buf := out[:0]
	buf = lenGCM.Seal(buf, lenNonce[:12], hdrLenPlain[:], nil)
	buf = payGCM.Seal(buf, payNonce[:12], respPlain[:], nil)
	_, err = v.Conn.Write(buf)
	return err
}
