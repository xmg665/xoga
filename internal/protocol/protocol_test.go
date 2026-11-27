package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

func startEchoTCPServer(t *testing.T) (host string, port uint16, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	h, pStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(pStr)
	return h, uint16(p), func() { _ = ln.Close() }
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestVLESSEndToEndRelayAndTrafficStats(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	tracker := stats.NewTracker(cfg)

	const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 7, UUIDOrPass: testUUID, DeviceLimit: 2},
	})
	idx := BuildUserIndex(users, 0)
	aclEng := acl.NewEngine(true, "", "", "", nil)

	srvPort := freeTCPPort(t)
	spec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}
	srv, err := NewServer(cfg, spec, tracker, idx, aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Build VLESS v0 TCP request header
	var req bytes.Buffer
	req.WriteByte(0x00) // version 0
	req.Write(users[0].UUIDBytes[:])
	req.WriteByte(0x00) // addon len 0
	req.WriteByte(0x01) // cmd TCP
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], echoPort)
	req.Write(pb[:])
	req.WriteByte(0x01) // IPv4
	req.Write(net.ParseIP(echoHost).To4())

	payload := []byte("hello-xoga-high-perf-vless-payload!")
	req.Write(payload)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	// Expect [0x00, 0x00] VLESS response header + echoed payload
	resp := make([]byte, 2+len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x00 || resp[1] != 0x00 || !bytes.Equal(resp[2:], payload) {
		t.Fatalf("unexpected VLESS response: %x", resp)
	}
	_ = conn.Close()
	time.Sleep(30 * time.Millisecond)

	harvest := tracker.HarvestTraffic(0)
	if len(harvest) != 1 || harvest[0].Upload != int64(len(payload)) || harvest[0].Download != int64(len(payload)) {
		t.Fatalf("unexpected VLESS traffic stats: %+v", harvest)
	}
}

func TestTrojanEndToEndRelay(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	tracker := stats.NewTracker(cfg)

	const pass = "my-trojan-secret-123"
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 9, UUIDOrPass: pass},
	})
	idx := BuildUserIndex(users, 0)
	srvPort := freeTCPPort(t)
	spec := &panel.NodeSpec{
		Protocol:   "trojan",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}
	srv, err := NewServer(cfg, spec, tracker, idx, acl.NewEngine(true, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	sum := sha256.Sum224([]byte(pass))
	hexPass := hex.EncodeToString(sum[:])

	var req bytes.Buffer
	req.WriteString(hexPass)
	req.WriteString("\r\n")
	req.WriteByte(0x01) // TCP Connect
	req.WriteByte(0x01) // IPv4
	req.Write(net.ParseIP(echoHost).To4())
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], echoPort)
	req.Write(pb[:])
	req.WriteString("\r\n")
	msg := []byte("trojan-zero-copy-echo-ok")
	req.Write(msg)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("mismatch: got %q want %q", got, msg)
	}
}

func TestShadowsocks2022MultiUserEIH(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	var srvKeyRaw, usrKeyRaw [16]byte
	_, _ = rand.Read(srvKeyRaw[:])
	_, _ = rand.Read(usrKeyRaw[:])
	srvKeyB64 := base64.StdEncoding.EncodeToString(srvKeyRaw[:])
	usrKeyB64 := base64.StdEncoding.EncodeToString(usrKeyRaw[:])

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	tracker := stats.NewTracker(cfg)
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 42, UUIDOrPass: usrKeyB64},
	})
	idx := BuildUserIndex(users, 16)
	srvPort := freeTCPPort(t)
	spec := &panel.NodeSpec{
		Protocol:   "shadowsocks",
		Cipher:     "2022-blake3-aes-128-gcm",
		ServerKey:  srvKeyB64,
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}
	srv, err := NewServer(cfg, spec, tracker, idx, acl.NewEngine(true, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Build SS-2022 Multi-User EIH client handshake
	var reqSalt [16]byte
	_, _ = rand.Read(reqSalt[:])

	var userEIH [16]byte
	blake3Hash("shadowsocks 2022 identity subkey", usrKeyRaw[:], userEIH[:])
	var idMat [32]byte
	copy(idMat[0:16], srvKeyRaw[:])
	copy(idMat[16:32], reqSalt[:])
	var idSubkey [16]byte
	blake3DeriveKey("shadowsocks 2022 identity subkey", idMat[:], idSubkey[:])
	idBlk, _ := aes.NewCipher(idSubkey[:])
	var eihEnc [16]byte
	idBlk.Encrypt(eihEnc[:], userEIH[:])

	var sessSubkey [16]byte
	var sessMat [32]byte
	copy(sessMat[0:16], usrKeyRaw[:])
	copy(sessMat[16:32], reqSalt[:])
	blake3DeriveKey("shadowsocks 2022 session subkey", sessMat[:], sessSubkey[:])
	cBlk, _ := aes.NewCipher(sessSubkey[:])
	cAEAD, _ := cipher.NewGCM(cBlk)

	msg := []byte("ss2022-eih-multiuser-test")
	var varPlain bytes.Buffer
	varPlain.WriteByte(0x01)
	varPlain.Write(net.ParseIP(echoHost).To4())
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], echoPort)
	varPlain.Write(pb[:])
	varPlain.Write([]byte{0x00, 0x00}) // padding len = 0
	varPlain.Write(msg)

	var fixedPlain [11]byte
	fixedPlain[0] = 0x00
	binary.BigEndian.PutUint64(fixedPlain[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(fixedPlain[9:11], uint16(varPlain.Len()))

	var wire bytes.Buffer
	wire.Write(reqSalt[:])
	wire.Write(eihEnc[:])
	var n0, n1 [12]byte
	n1[0] = 1
	wire.Write(cAEAD.Seal(nil, n0[:], fixedPlain[:], nil))
	wire.Write(cAEAD.Seal(nil, n1[:], varPlain.Bytes(), nil))
	if _, err := conn.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}

	// Read SS2022 server response: srvSalt(16) + AEAD(1+8+16+2 = 27 + 16 = 43) + AEAD(len(msg)+16)
	var srvSalt [16]byte
	if _, err := io.ReadFull(conn, srvSalt[:]); err != nil {
		t.Fatal(err)
	}
	var respSubkey [16]byte
	copy(sessMat[0:16], usrKeyRaw[:])
	copy(sessMat[16:32], srvSalt[:])
	blake3DeriveKey("shadowsocks 2022 session subkey", sessMat[:], respSubkey[:])
	sBlk, _ := aes.NewCipher(respSubkey[:])
	sAEAD, _ := cipher.NewGCM(sBlk)

	respHdrEnc := make([]byte, 27+16)
	if _, err := io.ReadFull(conn, respHdrEnc); err != nil {
		t.Fatal(err)
	}
	respHdrPlain, err := sAEAD.Open(nil, n0[:], respHdrEnc, nil)
	if err != nil {
		t.Fatalf("decrypt SS2022 response header failed: %v", err)
	}
	firstLen := int(binary.BigEndian.Uint16(respHdrPlain[25:27]))
	chunkEnc := make([]byte, firstLen+16)
	if _, err := io.ReadFull(conn, chunkEnc); err != nil {
		t.Fatal(err)
	}
	echoed, err := sAEAD.Open(nil, n1[:], chunkEnc, nil)
	if err != nil || !bytes.Equal(echoed, msg) {
		t.Fatalf("SS2022 echoed mismatch: %q err=%v", echoed, err)
	}
}

func BenchmarkHotPathZeroAllocs(b *testing.B) {
	u := stats.NewUserEntry(1, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	idx := BuildUserIndex([]*stats.UserEntry{u}, 0)
	keyUUID := u.UUIDBytes
	keyTrojan := u.TrojanHash

	b.Run("BufPool_GetPut_32KB", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			bp := bufpool.Get(bufpool.LargeSize)
			bufpool.Put(bp)
		}
	})

	b.Run("VLESS_UUID_O1_Lookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if idx.ByUUID[keyUUID] == nil {
				b.Fatal("missing")
			}
		}
	})

	b.Run("Trojan_SHA224_O1_Lookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if idx.ByTrojan[keyTrojan] == nil {
				b.Fatal("missing")
			}
		}
	})

	b.Run("Atomic_Traffic_Add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			u.AddUpload(1460)
			u.AddDownload(1460)
		}
	})
}
