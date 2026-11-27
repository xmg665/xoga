package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// Regression (M2): a short SNI-peek timeout firing mid-AEAD-chunk must preserve
// already-read bytes and resume decryption cleanly on the next Read without
// corrupting the stream or overwriting caller deadlines.
func TestVMessMidChunkTimeoutPreservesStream(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	var reqKey, reqIV [16]byte
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])

	vc, err := newVMessStreamConn(srvConn, srvConn, reqKey, reqIV, 0x22, 0x05, 0x03, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.releaseReadBuf()

	// Build a valid AES-128-GCM VMess chunk with chunk masking (opt=0x05)
	plainMsg := []byte("hello-split-vmess-aead-chunk-payload!")
	blk, _ := aes.NewCipher(reqKey[:])
	gcm, _ := cipher.NewGCM(blk)
	var nonce [12]byte
	copy(nonce[2:12], reqIV[2:12])
	sealed := gcm.Seal(nil, nonce[:], plainMsg, nil)

	// Compute the first Shake128 size mask
	tmpVC, _ := newVMessStreamConn(cliConn, cliConn, reqKey, reqIV, 0x22, 0x05, 0x03, false, false)
	sizeMask := tmpVC.nextMask(tmpVC.readMask)

	var frame bytes.Buffer
	var sz [2]byte
	binary.BigEndian.PutUint16(sz[:], uint16(len(sealed))^sizeMask)
	frame.Write(sz[:])
	frame.Write(sealed)
	raw := frame.Bytes()

	// Send header + first 7 bytes of ciphertext, pause 120ms, then send remainder
	go func() {
		_, _ = cliConn.Write(raw[:2+7])
		time.Sleep(120 * time.Millisecond)
		_, _ = cliConn.Write(raw[2+7:])
	}()

	// First Read with a 40ms deadline (simulates 150ms SNI peek timing out mid-chunk)
	_ = vc.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	buf := make([]byte, 128)
	n, rerr := vc.Read(buf)
	var ne net.Error
	if n != 0 || !errors.As(rerr, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout on partial chunk, got n=%d err=%v", n, rerr)
	}

	// Next Read after clearing deadline must seamlessly resume and decrypt intact payload
	_ = vc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr = vc.Read(buf)
	if rerr != nil {
		t.Fatalf("resumed VMess Read failed: %v", rerr)
	}
	if !bytes.Equal(buf[:n], plainMsg) {
		t.Fatalf("decrypted mismatch: got %q want %q", buf[:n], plainMsg)
	}
}

// Regression (M2): Shadowsocks AEAD Read must preserve partial encrypted length
// headers and partial chunk bodies across short timeouts without stream desync.
func TestShadowsocksMidChunkTimeoutPreservesStream(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	cs, err := parseSSCipher("aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	subkey := make([]byte, 16)
	_, _ = rand.Read(subkey)
	aead, err := cs.makeAEAD(subkey)
	if err != nil {
		t.Fatal(err)
	}

	ssConn := &ssAEADStreamConn{
		Conn:     srvConn,
		cs:       cs,
		readAEAD: aead,
	}
	defer ssConn.Close()

	plainMsg := []byte("hello-split-shadowsocks-aead-chunk!")
	var n0, n1 [12]byte
	n1[0] = 1
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(plainMsg)))
	encLen := aead.Seal(nil, n0[:], lenPlain[:], nil)
	encBody := aead.Seal(nil, n1[:], plainMsg, nil)
	raw := append(encLen, encBody...)

	// Split both mid-header (at byte 9) and mid-body (at byte 18+8)
	go func() {
		_, _ = cliConn.Write(raw[:9])
		time.Sleep(80 * time.Millisecond)
		_, _ = cliConn.Write(raw[9 : 18+8])
		time.Sleep(80 * time.Millisecond)
		_, _ = cliConn.Write(raw[18+8:])
	}()

	buf := make([]byte, 128)
	var ne net.Error

	_ = ssConn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if n, err := ssConn.Read(buf); n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout mid-header, got n=%d err=%v", n, err)
	}

	_ = ssConn.SetReadDeadline(time.Now().Add(90 * time.Millisecond))
	if n, err := ssConn.Read(buf); n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout mid-body, got n=%d err=%v", n, err)
	}

	_ = ssConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ssConn.Read(buf)
	if err != nil {
		t.Fatalf("resumed SS Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], plainMsg) {
		t.Fatalf("decrypted SS mismatch: got %q want %q", buf[:n], plainMsg)
	}
}

// Regression: malicious protobuf length varint must not integer-overflow and panic.
func TestDecodeVLESSAddonFlowMaliciousVarint(t *testing.T) {
	// field 1 (wire type 2 = 0x0a), varint = 0x7fffffffffffffff
	malicious := []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 'x'}
	if got := decodeVLESSAddonFlow(malicious); got != "" {
		t.Fatalf("expected empty flow for overflow varint, got %q", got)
	}
}
