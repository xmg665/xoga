package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
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

	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/stats"
)

const vmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

func vmessCmdKey(uuid [16]byte) [16]byte {
	h := md5.New()
	h.Write(uuid[:])
	h.Write([]byte(vmessMagic))
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// vmessKDF derives keys per V2Ray/Xray VMess AEAD specification (`HMAC-SHA256` nested KDF).
func vmessKDF(key []byte, path ...string) []byte {
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

// handleVMess implements VMess AEAD (`AuthID` + AEAD request header + AES-128-GCM / ChaCha20-Poly1305 / Zero body).
func (s *Server) handleVMess(conn net.Conn) {
	var authID [16]byte
	if _, err := io.ReadFull(conn, authID[:]); err != nil {
		return
	}

	idx := s.userIdx.Load()
	if idx == nil || len(idx.VMessUsers) == 0 {
		return
	}

	now := time.Now().Unix()
	var matched *VMessUserEntry
	var plainAuth [16]byte
	for i := range idx.VMessUsers {
		cand := &idx.VMessUsers[i]
		// Derive AuthID AES-128 key via KDF16(cmdKey, "AES Auth ID Encryption")
		authKey := vmessKDF(cand.CmdKey[:], "AES Auth ID Encryption")[:16]
		blk, err := aes.NewCipher(authKey)
		if err != nil {
			continue
		}
		blk.Decrypt(plainAuth[:], authID[:])
		crc := crc32.ChecksumIEEE(plainAuth[:12])
		if crc != binary.BigEndian.Uint32(plainAuth[12:16]) {
			continue
		}
		ts := int64(binary.BigEndian.Uint64(plainAuth[:8]))
		if math.Abs(float64(now-ts)) <= 120 {
			matched = cand
			break
		}
	}
	if matched == nil {
		return
	}

	// Read 18-byte encrypted header length + 8-byte connection nonce
	var encLenAndNonce [26]byte
	if _, err := io.ReadFull(conn, encLenAndNonce[:]); err != nil {
		return
	}
	encHdrLen := encLenAndNonce[:18]
	connNonce := encLenAndNonce[18:26]

	lenKey := vmessKDF(matched.CmdKey[:], "VMess Header AEAD Key_Length", string(authID[:]), string(connNonce))[:16]
	lenNonce := vmessKDF(matched.CmdKey[:], "VMess Header AEAD Nonce_Length", string(authID[:]), string(connNonce))[:12]
	lenBlk, err := aes.NewCipher(lenKey)
	if err != nil {
		return
	}
	lenGCM, err := cipher.NewGCM(lenBlk)
	if err != nil {
		return
	}
	var hdrLenBytes [2]byte
	if _, err := lenGCM.Open(hdrLenBytes[:0], lenNonce, encHdrLen, authID[:]); err != nil {
		return
	}
	hdrLen := int(binary.BigEndian.Uint16(hdrLenBytes[:])) + 16
	if hdrLen <= 16 || hdrLen > 2048 {
		return
	}

	encHdr := make([]byte, hdrLen)
	if _, err := io.ReadFull(conn, encHdr); err != nil {
		return
	}

	payKey := vmessKDF(matched.CmdKey[:], "VMess Header AEAD Key", string(authID[:]), string(connNonce))[:16]
	payNonce := vmessKDF(matched.CmdKey[:], "VMess Header AEAD Nonce", string(authID[:]), string(connNonce))[:12]
	payBlk, err := aes.NewCipher(payKey)
	if err != nil {
		return
	}
	payGCM, err := cipher.NewGCM(payBlk)
	if err != nil {
		return
	}
	hdrPlain, err := payGCM.Open(encHdr[:0], payNonce, encHdr, authID[:])
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

	addrReader := bytes.NewReader(hdrPlain[40 : len(hdrPlain)-4-pLen])
	destHost, err := parseVLESSAddr(addrReader)
	if err != nil || cmd != 0x01 {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	vmConn, err := newVMessStreamConn(conn, reqBodyKey, reqBodyIV, respV, opt, secType)
	if err != nil {
		return
	}
	s.connectAndRelay(vmConn, matched.User, destHost, destPort, nil)
}

type vmessStreamConn struct {
	net.Conn
	respV        byte
	optChunkMask bool
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

func newVMessStreamConn(c net.Conn, reqKey, reqIV [16]byte, respV, opt, secType byte) (*vmessStreamConn, error) {
	rk := sha256.Sum256(reqKey[:])
	riv := sha256.Sum256(reqIV[:])
	vc := &vmessStreamConn{
		Conn:         c,
		respV:        respV,
		optChunkMask: (opt & 0x04) != 0,
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
	default: // None / Zero
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

func (v *vmessStreamConn) Read(p []byte) (int, error) {
	v.readMu.Lock()
	defer v.readMu.Unlock()

	if len(v.leftover) > 0 {
		n := copy(p, v.leftover)
		v.leftover = v.leftover[n:]
		return n, nil
	}

	var lb [2]byte
	if _, err := io.ReadFull(v.Conn, lb[:]); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint16(lb[:]) ^ v.nextMask(v.readMask)
	if v.readAEAD != nil && size == uint16(v.readAEAD.Overhead()) {
		return 0, io.EOF
	}
	if size == 0 {
		return 0, io.EOF
	}

	bp := bufpool.Get(int(size))
	defer bufpool.Put(bp)
	chunk := (*bp)[:size]
	if _, err := io.ReadFull(v.Conn, chunk); err != nil {
		return 0, err
	}

	plain := chunk
	if v.readAEAD != nil {
		var nonce [12]byte
		binary.BigEndian.PutUint16(nonce[0:2], v.readCount)
		copy(nonce[2:12], v.reqIV[2:12])
		v.readCount++
		var err error
		plain, err = v.readAEAD.Open(chunk[:0], nonce[:], chunk, nil)
		if err != nil {
			return 0, err
		}
	}

	n := copy(p, plain)
	if n < len(plain) {
		v.leftover = append(v.leftover[:0], plain[n:]...)
	}
	return n, nil
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
	const maxPlain = 16384 - 64
	for len(p) > 0 {
		part := p
		if len(part) > maxPlain {
			part = p[:maxPlain]
		}
		p = p[len(part):]

		bp := bufpool.Get(2 + len(part) + 16)
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
		wireSize := uint16(len(out)-2) ^ v.nextMask(v.writeMask)
		binary.BigEndian.PutUint16(out[0:2], wireSize)
		_, err := v.Conn.Write(out)
		bufpool.Put(bp)
		if err != nil {
			return total, err
		}
		total += len(part)
	}
	return total, nil
}

func (v *vmessStreamConn) sendAEADResponseHeader() error {
	respPlain := [4]byte{v.respV, 0x00, 0x00, 0x00}
	lenKey := vmessKDF(v.respKey[:], "AEAD Resp Header Len Key")[:16]
	lenNonce := vmessKDF(v.respIV[:], "AEAD Resp Header Len IV")[:12]
	lenBlk, err := aes.NewCipher(lenKey)
	if err != nil {
		return err
	}
	lenGCM, err := cipher.NewGCM(lenBlk)
	if err != nil {
		return err
	}
	var hdrLenPlain [2]byte
	binary.BigEndian.PutUint16(hdrLenPlain[:], 4)

	payKey := vmessKDF(v.respKey[:], "AEAD Resp Header Key")[:16]
	payNonce := vmessKDF(v.respIV[:], "AEAD Resp Header IV")[:12]
	payBlk, err := aes.NewCipher(payKey)
	if err != nil {
		return err
	}
	payGCM, err := cipher.NewGCM(payBlk)
	if err != nil {
		return err
	}

	out := make([]byte, 0, 18+20)
	out = lenGCM.Seal(out, lenNonce, hdrLenPlain[:], nil)
	out = payGCM.Seal(out, payNonce, respPlain[:], nil)
	_, err = v.Conn.Write(out)
	return err
}

var _ = stats.ErrIPLimit
