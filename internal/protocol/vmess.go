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
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"math"
	"net"
	"sync"
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

func checkVMessCandidate(cand *VMessUserEntry, authID *[16]byte, now int64) bool {
	var plainAuth [16]byte
	cand.AuthBlock.Decrypt(plainAuth[:], authID[:])
	if crc32.ChecksumIEEE(plainAuth[:12]) != binary.BigEndian.Uint32(plainAuth[12:16]) {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(plainAuth[:8]))
	return math.Abs(float64(now-ts)) <= 120
}

// handleVMess implements VMess AEAD (`AuthID` + AEAD request header + AES-128-GCM / ChaCha20-Poly1305 / Zero body)
// for both TCP (`cmd=0x01`) and UDP-over-stream (`cmd=0x02`), with O(1) client-IP user hinting & anti-replay.
func (s *Server) handleVMess(conn net.Conn) {
	br := bufio.NewReaderSize(conn, 4096)

	var authID [16]byte
	if _, err := io.ReadFull(br, authID[:]); err != nil {
		return
	}

	idx := s.userIdx.Load()
	if idx == nil || len(idx.VMessUsers) == 0 {
		return
	}

	now := time.Now().Unix()
	clientIP := relay.ExtractClientIP(conn.RemoteAddr())

	var matched *VMessUserEntry
	// 1. O(1) lock-free IP->User hint fast path (1 AES block decrypt instead of scanning 5,000+ users!)
	if hintIdx, ok := s.ipHints.Lookup(clientIP); ok && hintIdx < len(idx.VMessUsers) {
		cand := &idx.VMessUsers[hintIdx]
		if checkVMessCandidate(cand, &authID, now) {
			matched = cand
		}
	}
	// 2. Fallback scan when IP is new or shared across multiple NAT users
	if matched == nil {
		for i := range idx.VMessUsers {
			cand := &idx.VMessUsers[i]
			if checkVMessCandidate(cand, &authID, now) {
				matched = cand
				s.ipHints.Store(clientIP, i)
				break
			}
		}
	}
	if matched == nil {
		return
	}

	// 3. Reject replayed AuthIDs after authentication succeeds (prevents GFW active replay probing)
	if s.replay.CheckAndMark(authID[:]) {
		return
	}

	// Read 18-byte encrypted header length + 8-byte connection nonce
	var encLenAndNonce [26]byte
	if _, err := io.ReadFull(br, encLenAndNonce[:]); err != nil {
		return
	}
	encHdrLen := encLenAndNonce[:18]
	connNonce := encLenAndNonce[18:26]

	lenKey := vmessKDF3(matched.CmdKey[:], kdfSaltHdrLenKey, authID[:], connNonce)
	lenNonce := vmessKDF3(matched.CmdKey[:], kdfSaltHdrLenIV, authID[:], connNonce)
	lenBlk, err := aes.NewCipher(lenKey[:16])
	if err != nil {
		return
	}
	lenGCM, err := cipher.NewGCM(lenBlk)
	if err != nil {
		return
	}
	var hdrLenBytes [2]byte
	if _, err := lenGCM.Open(hdrLenBytes[:0], lenNonce[:12], encHdrLen, authID[:]); err != nil {
		return
	}
	hdrLen := int(binary.BigEndian.Uint16(hdrLenBytes[:])) + 16
	if hdrLen <= 16 || hdrLen > 2048 {
		return
	}

	var stackHdr [512]byte
	var encHdr []byte
	if hdrLen <= len(stackHdr) {
		encHdr = stackHdr[:hdrLen]
	} else {
		encHdr = make([]byte, hdrLen)
	}
	if _, err := io.ReadFull(br, encHdr); err != nil {
		return
	}

	payKey := vmessKDF3(matched.CmdKey[:], kdfSaltHdrKey, authID[:], connNonce)
	payNonce := vmessKDF3(matched.CmdKey[:], kdfSaltHdrIV, authID[:], connNonce)
	payBlk, err := aes.NewCipher(payKey[:16])
	if err != nil {
		return
	}
	payGCM, err := cipher.NewGCM(payBlk)
	if err != nil {
		return
	}
	hdrPlain, err := payGCM.Open(encHdr[:0], payNonce[:12], encHdr, authID[:])
	if err != nil || len(hdrPlain) < 41 {
		return
	}

	// Verify FNV1a32 checksum at end of VMess command header
	fnvHash := fnv.New32a()
	_, _ = fnvHash.Write(hdrPlain[:len(hdrPlain)-4])
	if fnvHash.Sum32() != binary.BigEndian.Uint32(hdrPlain[len(hdrPlain)-4:]) || hdrPlain[0] != 0x01 {
		return
	}

	var reqBodyIV, reqBodyKey [16]byte
	copy(reqBodyIV[:], hdrPlain[1:17])
	copy(reqBodyKey[:], hdrPlain[17:33])
	respV := hdrPlain[33]
	opt := hdrPlain[34]
	pLen := int(hdrPlain[35] >> 4)
	secType := hdrPlain[35] & 0x0F
	cmd := hdrPlain[37]
	destPort := binary.BigEndian.Uint16(hdrPlain[38:40])

	if len(hdrPlain)-4-pLen <= 40 {
		return
	}
	addrReader := bytes.NewReader(hdrPlain[40 : len(hdrPlain)-4-pLen])
	destHost, err := parseVLESSAddr(addrReader)
	if err != nil || (cmd != 0x01 && cmd != 0x02) {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	vmConn, err := newVMessStreamConn(conn, br, reqBodyKey, reqBodyIV, respV, opt, secType)
	if err != nil {
		return
	}
	if cmd == 0x02 {
		s.handleVMessUDP(vmConn, matched.User, destHost, destPort)
		return
	}
	s.connectAndRelay(vmConn, matched.User, destHost, destPort, nil)
}

func (s *Server) handleVMessUDP(vmConn *vmessStreamConn, user *stats.UserEntry, destHost string, destPort uint16) {
	clientIP := relay.ExtractClientIP(vmConn.RemoteAddr())
	if err := user.AcquireConn(clientIP, s.tracker.IPTTLSeconds(), s.tracker.RedisLimiter()); err != nil {
		return
	}
	defer user.ReleaseConn()

	route := s.aclEng.Load().DecideForNode(s.cfg.NodeID, destHost, destPort, "", "")
	if route.Action == acl.ActionBlock {
		return
	}

	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	udpAddr, err := relay.ResolveUDPTargetForRoute(rctx, destHost, destPort, route, s.dnsRes)
	rcancel()
	if err != nil {
		return
	}
	localUDP := relay.LocalUDPAddrForRoute(route, udpAddr.IP.To4() == nil)
	targetUDP, err := net.DialUDP("udp", localUDP, udpAddr)
	if err != nil {
		return
	}
	defer targetUDP.Close()

	idleDur := time.Duration(s.cfg.UDPIdleSec) * time.Second
	if idleDur < 10*time.Second {
		idleDur = 60 * time.Second
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		bp := bufpool.Get(bufpool.MaxUDPSize)
		buf := *bp
		defer bufpool.Put(bp)
		for {
			_ = targetUDP.SetReadDeadline(time.Now().Add(idleDur))
			n, err := targetUDP.Read(buf)
			if err != nil {
				return
			}
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
			break
		}
		if n == 0 {
			continue
		}
		if ul := user.EffectiveLimiter(); ul != nil {
			ul.Wait(n)
		}
		s.tracker.NodeLimiter.Wait(n)
		user.AddUpload(int64(n))
		_, _ = targetUDP.Write(inBuf[:n])
	}

	_ = targetUDP.Close()
	<-done
}

type vmessStreamConn struct {
	net.Conn
	reader       io.Reader
	respV        byte
	optChunkMask bool
	optGlobalPad bool
	secType      byte

	reqKey  [16]byte
	reqIV   [16]byte
	respKey [16]byte
	respIV  [16]byte

	readMu    sync.Mutex
	readAEAD  cipher.AEAD
	readMask  sha3.ShakeHash
	readCount uint16
	leftover  []byte

	writeMu    sync.Mutex
	sentResp   bool
	writeAEAD  cipher.AEAD
	writeMask  sha3.ShakeHash
	writeCount uint16
}

func newVMessStreamConn(c net.Conn, br io.Reader, reqKey, reqIV [16]byte, respV, opt, secType byte) (*vmessStreamConn, error) {
	rk := sha256.Sum256(reqKey[:])
	riv := sha256.Sum256(reqIV[:])
	if br == nil {
		br = c
	}
	chunkMask := (opt & 0x04) != 0
	vc := &vmessStreamConn{
		Conn:         c,
		reader:       br,
		respV:        respV,
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
	default: // None (0x05) / Zero (0x06)
		return nil, nil
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

func (v *vmessStreamConn) readSingleChunk(dst []byte) (int, error) {
	v.readMu.Lock()
	defer v.readMu.Unlock()

	padLen := 0
	if v.optGlobalPad {
		padLen = int(v.nextMask(v.readMask) % 64)
	}
	sizeMask := v.nextMask(v.readMask)

	var lb [2]byte
	if _, err := io.ReadFull(v.reader, lb[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(lb[:]) ^ sizeMask)

	overhead := 0
	if v.readAEAD != nil {
		overhead = v.readAEAD.Overhead()
	}
	if size == overhead+padLen {
		if size > 0 {
			var eofBuf [128]byte
			_, _ = io.ReadFull(v.reader, eofBuf[:size])
		}
		return 0, io.EOF
	}
	if size <= overhead+padLen || size > 65535 {
		return 0, io.EOF
	}

	bp := bufpool.Get(size)
	defer bufpool.Put(bp)
	chunk := (*bp)[:size]
	if _, err := io.ReadFull(v.reader, chunk); err != nil {
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
			return 0, err
		}
	}
	n := copy(dst, plain)
	if n < len(plain) {
		v.leftover = append(v.leftover[:0], plain[n:]...)
	}
	return n, nil
}

func (v *vmessStreamConn) Read(p []byte) (int, error) {
	v.readMu.Lock()
	if len(v.leftover) > 0 {
		n := copy(p, v.leftover)
		v.leftover = v.leftover[n:]
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
	sizeMask := v.nextMask(v.writeMask)

	bp := bufpool.Get(2 + len(part) + 16 + padLen)
	out := (*bp)[:2]
	if v.writeAEAD != nil {
		var nonce [12]byte
		binary.BigEndian.PutUint16(nonce[0:2], v.writeCount)
		copy(nonce[2:12], v.respIV[2:12])
		v.writeCount++
		out = v.writeAEAD.Seal(out, nonce[:], part, nil)
	} else {
		out = append(out, part...)
	}
	if padLen > 0 {
		padStart := len(out)
		out = out[:padStart+padLen]
		_, _ = rand.Read(out[padStart:])
	}
	wireSize := uint16(len(out)-2) ^ sizeMask
	binary.BigEndian.PutUint16(out[0:2], wireSize)
	_, err := v.Conn.Write(out)
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
