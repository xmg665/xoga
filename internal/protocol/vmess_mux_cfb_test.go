package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

func buildTestVMessAEADHdr(uuidBytes [16]byte, reqKey, reqIV [16]byte, opt, sec, cmd byte, host string, port uint16) []byte {
	cmdKey := vmessCmdKey(uuidBytes)
	var hdr []byte
	hdr = append(hdr, 0x01)
	hdr = append(hdr, reqIV[:]...)
	hdr = append(hdr, reqKey[:]...)
	hdr = append(hdr, 0x22, opt, sec, 0x00, cmd)
	if cmd != 0x03 {
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], port)
		hdr = append(hdr, pb[:]...)
		hdr = append(hdr, 0x02, byte(len(host)))
		hdr = append(hdr, host...)
	}
	fh := fnv.New32a()
	_, _ = fh.Write(hdr)
	var fb [4]byte
	binary.BigEndian.PutUint32(fb[:], fh.Sum32())
	hdr = append(hdr, fb[:]...)

	var authPlain [16]byte
	binary.BigEndian.PutUint64(authPlain[0:8], uint64(time.Now().Unix()))
	_, _ = rand.Read(authPlain[8:12])
	binary.BigEndian.PutUint32(authPlain[12:16], crc32.ChecksumIEEE(authPlain[0:12]))
	authBlk, _ := aes.NewCipher(vmessKDF(cmdKey[:], "AES Auth ID Encryption")[:16])
	var authID [16]byte
	authBlk.Encrypt(authID[:], authPlain[:])

	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	lenPlain := [2]byte{byte(len(hdr) >> 8), byte(len(hdr))}
	lenBlk, _ := aes.NewCipher(vmessKDF(cmdKey[:], "VMess Header AEAD Key_Length", string(authID[:]), string(nonce[:]))[:16])
	lenGCM, _ := cipher.NewGCM(lenBlk)
	encLen := lenGCM.Seal(nil, vmessKDF(cmdKey[:], "VMess Header AEAD Nonce_Length", string(authID[:]), string(nonce[:]))[:12], lenPlain[:], authID[:])

	hdrBlk, _ := aes.NewCipher(vmessKDF(cmdKey[:], "VMess Header AEAD Key", string(authID[:]), string(nonce[:]))[:16])
	hdrGCM, _ := cipher.NewGCM(hdrBlk)
	encHdr := hdrGCM.Seal(nil, vmessKDF(cmdKey[:], "VMess Header AEAD Nonce", string(authID[:]), string(nonce[:]))[:12], hdr, authID[:])

	var out []byte
	out = append(out, authID[:]...)
	out = append(out, encLen...)
	out = append(out, nonce[:]...)
	out = append(out, encHdr...)
	return out
}

func TestVMessMuxCoolTCPAndAES128CFBLegacyCipher(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	tr := stats.NewTracker(cfg)
	const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 55, UUIDOrPass: testUUID},
	})
	srvPort := freeTCPPort(t)
	spec := &panel.NodeSpec{
		Protocol:   "vmess",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vmess", users, 0), acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// 1. Test VMess with AES-128-CFB (sec=0x01) + ChunkMasking (opt=0x05)
	c1, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))

	var reqKey, reqIV [16]byte
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])
	hdr1 := buildTestVMessAEADHdr(users[0].UUIDBytes, reqKey, reqIV, 0x05, 0x01, 0x01, echoHost, echoPort)

	msg1 := []byte("hello-vmess-aes-128-cfb-legacy-cipher!")
	rm := sha3.NewShake128()
	_, _ = rm.Write(reqIV[:])
	var mb [2]byte
	_, _ = rm.Read(mb[:])
	fh := fnv.New32a()
	_, _ = fh.Write(msg1)

	var plainChunk bytes.Buffer
	_ = binary.Write(&plainChunk, binary.BigEndian, uint16(4+len(msg1))^binary.BigEndian.Uint16(mb[:]))
	_ = binary.Write(&plainChunk, binary.BigEndian, fh.Sum32())
	plainChunk.Write(msg1)

	reqBlk, _ := aes.NewCipher(reqKey[:])
	cfbEnc := cipher.NewCFBEncrypter(reqBlk, reqIV[:])
	encChunk := make([]byte, plainChunk.Len())
	cfbEnc.XORKeyStream(encChunk, plainChunk.Bytes())

	if _, err := c1.Write(append(hdr1, encChunk...)); err != nil {
		t.Fatal(err)
	}
	var respAEADHdr [38]byte
	if _, err := io.ReadFull(c1, respAEADHdr[:]); err != nil {
		t.Fatalf("CFB resp hdr read failed: %v", err)
	}
	rk := sha256.Sum256(reqKey[:])
	riv := sha256.Sum256(reqIV[:])
	respBlk, _ := aes.NewCipher(rk[:16])
	cfbDec := &cipher.StreamReader{S: cipher.NewCFBDecrypter(respBlk, riv[:16]), R: c1}

	wm := sha3.NewShake128()
	_, _ = wm.Write(riv[:16])
	var wmb [2]byte
	_, _ = wm.Read(wmb[:])
	var rSizeB [2]byte
	if _, err := io.ReadFull(cfbDec, rSizeB[:]); err != nil {
		t.Fatal(err)
	}
	rSize := int(binary.BigEndian.Uint16(rSizeB[:]) ^ binary.BigEndian.Uint16(wmb[:]))
	rBody := make([]byte, rSize)
	if _, err := io.ReadFull(cfbDec, rBody); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rBody[4:], msg1) {
		t.Fatalf("CFB echo mismatch: got %q want %q", rBody[4:], msg1)
	}

	// 2. Test VMess Mux.Cool (`v1.mux.cool` TCP sub-session sid=1)
	c2, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])
	hdr2 := buildTestVMessAEADHdr(users[0].UUIDBytes, reqKey, reqIV, 0x01, 0x05, 0x01, "v1.mux.cool", 666)

	// Build Mux.Cool SessionStatusNew (0x01) + OptionData (0x01) for TCP (0x01) -> echoHost:echoPort
	muxMsg := []byte("hello-mux-cool-over-vmess!")
	var meta bytes.Buffer
	_ = binary.Write(&meta, binary.BigEndian, uint16(7)) // sid=7
	meta.WriteByte(0x01)                                 // New
	meta.WriteByte(0x01)                                 // OptionData
	meta.WriteByte(0x01)                                 // Net=TCP
	_ = binary.Write(&meta, binary.BigEndian, echoPort)
	meta.WriteByte(0x01) // IPv4
	meta.Write(net.ParseIP(echoHost).To4())

	var muxFrame bytes.Buffer
	_ = binary.Write(&muxFrame, binary.BigEndian, uint16(meta.Len()))
	muxFrame.Write(meta.Bytes())
	_ = binary.Write(&muxFrame, binary.BigEndian, uint16(len(muxMsg)))
	muxFrame.Write(muxMsg)

	var vmChunk bytes.Buffer
	_ = binary.Write(&vmChunk, binary.BigEndian, uint16(muxFrame.Len()))
	vmChunk.Write(muxFrame.Bytes())

	if _, err := c2.Write(append(hdr2, vmChunk.Bytes()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c2, respAEADHdr[:]); err != nil {
		t.Fatalf("Mux resp hdr read failed: %v", err)
	}
	var chunkLen [2]byte
	if _, err := io.ReadFull(c2, chunkLen[:]); err != nil {
		t.Fatal(err)
	}
	muxResp := make([]byte, binary.BigEndian.Uint16(chunkLen[:]))
	if _, err := io.ReadFull(c2, muxResp); err != nil {
		t.Fatal(err)
	}
	// muxResp = [0x00, 0x04, 0x00, 0x07, 0x02(Keep), 0x01(Data), dlen_hi, dlen_lo, data...]
	if len(muxResp) < 8 || binary.BigEndian.Uint16(muxResp[2:4]) != 7 || !bytes.Equal(muxResp[8:], muxMsg) {
		t.Fatalf("Mux.Cool TCP echo mismatch: raw=%x", muxResp)
	}

	// Send SessionStatusKeep (0x02) follow-up chunk on sid=7 + SessionStatusEnd (0x03) half-close
	muxMsg2 := []byte("-second-chunk-keep")
	var keepFrame bytes.Buffer
	_ = binary.Write(&keepFrame, binary.BigEndian, uint16(4))
	_ = binary.Write(&keepFrame, binary.BigEndian, uint16(7))
	keepFrame.WriteByte(0x02) // Keep
	keepFrame.WriteByte(0x01) // OptionData
	_ = binary.Write(&keepFrame, binary.BigEndian, uint16(len(muxMsg2)))
	keepFrame.Write(muxMsg2)
	// Append End frame (graceful client half-close)
	_ = binary.Write(&keepFrame, binary.BigEndian, uint16(4))
	_ = binary.Write(&keepFrame, binary.BigEndian, uint16(7))
	keepFrame.WriteByte(0x03) // End
	keepFrame.WriteByte(0x00) // no error

	var vmKeepChunk bytes.Buffer
	_ = binary.Write(&vmKeepChunk, binary.BigEndian, uint16(keepFrame.Len()))
	vmKeepChunk.Write(keepFrame.Bytes())
	if _, err := c2.Write(vmKeepChunk.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c2, chunkLen[:]); err != nil {
		t.Fatal(err)
	}
	muxResp2 := make([]byte, binary.BigEndian.Uint16(chunkLen[:]))
	if _, err := io.ReadFull(c2, muxResp2); err != nil {
		t.Fatal(err)
	}
	if len(muxResp2) < 8 || binary.BigEndian.Uint16(muxResp2[2:4]) != 7 || !bytes.Equal(muxResp2[8:], muxMsg2) {
		t.Fatalf("Mux.Cool Keep echo mismatch: raw=%x", muxResp2)
	}

	// 3. Test VMess cmd=0x03 (RequestCommandMux omitting address in VMess header)
	c3, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	_ = c3.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])
	hdr3 := buildTestVMessAEADHdr(users[0].UUIDBytes, reqKey, reqIV, 0x01, 0x05, 0x03, "", 0)
	if _, err := c3.Write(append(hdr3, vmChunk.Bytes()...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c3, respAEADHdr[:]); err != nil {
		t.Fatalf("cmd=0x03 resp hdr read failed: %v", err)
	}
	if _, err := io.ReadFull(c3, chunkLen[:]); err != nil {
		t.Fatal(err)
	}
	muxResp3 := make([]byte, binary.BigEndian.Uint16(chunkLen[:]))
	if _, err := io.ReadFull(c3, muxResp3); err != nil {
		t.Fatal(err)
	}
	if len(muxResp3) < 8 || !bytes.Equal(muxResp3[8:], muxMsg) {
		t.Fatalf("cmd=0x03 Mux.Cool echo mismatch: raw=%x", muxResp3)
	}
}
