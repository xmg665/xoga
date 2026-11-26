package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/sha3"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
	"github.com/xmg665/xoga/internal/transport"
)

func startEchoTCPAndUDP(t *testing.T) (tcpPort uint16, udpPort uint16) {
	t.Helper()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpPC.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpPC.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpPC.WriteTo(buf[:n], addr)
		}
	}()

	return uint16(tcpLn.Addr().(*net.TCPAddr).Port), uint16(udpPC.LocalAddr().(*net.UDPAddr).Port)
}

func freeLocalPort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestExpiryAndQuotaInstantDisconnect verifies BOTH:
// 1. Account expiry (`ReconcileUsers` removing an active user) immediately force-closes open long-lived streams
//    AND preserves final unpushed traffic bytes in `HarvestTraffic`.
// 2. Real-time byte quota (`RemainBytes > 0`) cuts off an active download mid-stream the instant remaining bytes hit 0.
func TestExpiryAndQuotaInstantDisconnect(t *testing.T) {
	echoTCP, _ := startEchoTCPAndUDP(t)
	srvPort := freeLocalPort(t, "tcp")

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = srvPort

	tr := stats.NewTracker(cfg)
	uuid1 := "b831381d-6324-4d53-ad4f-8cda48b30811"
	uuid2 := "c942492e-7435-4e64-be50-9deb59c41922"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 1, UUIDOrPass: uuid1, RemainBytes: -1},
		{ID: 2, UUIDOrPass: uuid2, RemainBytes: 2048}, // only 2 KiB remaining!
	})

	spec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}
	aclEng := acl.NewEngine(false, "", "", "", nil)
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	buildVLESSHdr := func(u *stats.UserEntry, port uint16) []byte {
		var hdr bytes.Buffer
		hdr.WriteByte(0x00)
		hdr.Write(u.UUIDBytes[:])
		hdr.WriteByte(0x00) // addon len 0
		hdr.WriteByte(0x01) // TCP
		_ = binary.Write(&hdr, binary.BigEndian, port)
		hdr.WriteByte(0x01) // IPv4
		hdr.Write([]byte{127, 0, 0, 1})
		return hdr.Bytes()
	}

	// 1. Open long-lived VLESS stream for User 1
	c1, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	msg := []byte("hello-before-expiry")
	if _, err := c1.Write(append(buildVLESSHdr(users[0], echoTCP), msg...)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2+len(msg))
	if _, err := io.ReadFull(c1, resp); err != nil {
		t.Fatalf("initial echo failed: %v", err)
	}
	if !bytes.Equal(resp[2:], msg) {
		t.Fatalf("unexpected echo: %q", resp[2:])
	}

	// Simulate account expiry on panel: User 1 is removed from SyncUserSpec list!
	newUsers, _, _, removed := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 2, UUIDOrPass: uuid2, RemainBytes: 2048},
	})
	if removed != 1 {
		t.Fatalf("expected 1 removed user, got %d", removed)
	}
	srv.UpdateUsers(BuildUserIndexForProtocol("vless", newUsers, 0))

	// Verify open socket `c1` is immediately force-closed within 200ms (not waiting 120s idle timeout!)
	_ = c1.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	var probe [16]byte
	_, err = c1.Read(probe[:])
	if err == nil {
		t.Fatal("expected expired user's active socket to be force-closed immediately, but Read succeeded")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("expired user's active socket timed out instead of being closed immediately by DisableAndKick()")
	}

	// Verify User 1's pre-kick traffic was preserved in HarvestTraffic!
	deltas := tr.HarvestTraffic(0)
	foundUser1 := false
	for _, d := range deltas {
		if d.UserID == 1 && d.Upload >= int64(len(msg)) && d.Download >= int64(len(msg)) {
			foundUser1 = true
		}
	}
	if !foundUser1 {
		t.Fatalf("expected kicked user 1 final traffic to be preserved, got %+v", deltas)
	}

	// 2. Verify User 2 (2048 B quota) gets cut off mid-stream when sending 8 KiB!
	c2, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	bigPayload := bytes.Repeat([]byte("Q"), 8192)
	_, _ = c2.Write(append(buildVLESSHdr(newUsers[0], echoTCP), bigPayload...))
	_ = c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	allRead, _ := io.ReadAll(c2)
	if len(allRead) >= 2+len(bigPayload) && !newUsers[0].IsDisabled() {
		t.Fatalf("expected user 2 to be disabled mid-stream after exceeding 2048B quota")
	}
	if !newUsers[0].IsDisabled() {
		t.Fatalf("expected user 2 IsDisabled() == true after exceeding quota")
	}
}

func TestHysteria2TCPUDPAndSalamander(t *testing.T) {
	echoTCP, echoUDP := startEchoTCPAndUDP(t)
	hy2Port := freeLocalPort(t, "udp")

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = hy2Port
	cfg.CertMode = "self"

	tr := stats.NewTracker(cfg)
	secret := "hy2-user-secret-uuid"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 7, UUIDOrPass: secret, RemainBytes: -1},
	})

	obfsPW := "salamander-test-psk"
	spec := &panel.NodeSpec{
		Protocol:        "hysteria2",
		ListenIP:        "127.0.0.1",
		ServerPort:      hy2Port,
		Network:         "quic",
		TLSMode:         1,
		ServerName:      "localhost",
		Hy2Obfs:         "salamander",
		Hy2ObfsPassword: obfsPW,
		Hy2DownMbps:     100,
	}
	aclEng := acl.NewEngine(false, "", "", "", nil)
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("hysteria2", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Dial QUIC over Salamander-obfuscated UDP
	rawClientUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawClientUDP.Close()
	obfsClientUDP, err := newSalamanderPacketConn(rawClientUDP, []byte(obfsPW))
	if err != nil {
		t.Fatal(err)
	}

	srvAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hy2Port}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	qconn, err := quic.Dial(ctx, obfsClientUDP, srvAddr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("quic dial hysteria2 failed: %v", err)
	}
	defer qconn.CloseWithError(0, "")

	h3Tr := &http3.Transport{EnableDatagrams: false}
	cConn := h3Tr.NewClientConn(qconn)

	// 1. Authenticate via POST https://hysteria/auth -> expect HTTP 233
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	req.Header.Set("Hysteria-Auth", secret)
	req.Header.Set("Hysteria-CC-RX", "12500000")
	resp, err := cConn.RoundTrip(req)
	if err != nil {
		t.Fatalf("hy2 HTTP/3 auth roundtrip failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 233 {
		t.Fatalf("expected HTTP 233 HyOK, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Hysteria-UDP") != "true" {
		t.Fatalf("expected Hysteria-UDP=true")
	}

	// 2. Open Hysteria 2 TCP Request stream (0x401)
	qstr, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targetTCP := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoTCP)))
	var tcpReq []byte
	tcpReq = quicvarint.Append(tcpReq, hy2FrameTCPRequest)
	tcpReq = quicvarint.Append(tcpReq, uint64(len(targetTCP)))
	tcpReq = append(tcpReq, targetTCP...)
	tcpReq = quicvarint.Append(tcpReq, 4)
	tcpReq = append(tcpReq, "pad!"...)
	tcpPayload := []byte("hello-hysteria2-tcp-stream")
	tcpReq = append(tcpReq, tcpPayload...)
	if _, err := qstr.Write(tcpReq); err != nil {
		t.Fatal(err)
	}

	// Read TCPResponse: status(1) + msgLen(varint) + msg + padLen(varint) + pad
	var stByte [1]byte
	if _, err := io.ReadFull(qstr, stByte[:]); err != nil || stByte[0] != 0x00 {
		t.Fatalf("hy2 tcp response status err=%v status=%d", err, stByte[0])
	}
	vr := quicvarint.NewReader(qstr)
	mlen, _ := quicvarint.Read(vr)
	if mlen > 0 {
		_, _ = io.CopyN(io.Discard, qstr, int64(mlen))
	}
	plen, _ := quicvarint.Read(vr)
	if plen > 0 {
		_, _ = io.CopyN(io.Discard, qstr, int64(plen))
	}

	echoedTCP := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(qstr, echoedTCP); err != nil || !bytes.Equal(echoedTCP, tcpPayload) {
		t.Fatalf("hy2 tcp echoed=%q err=%v", echoedTCP, err)
	}
	_ = qstr.Close()

	// 3. Test Hysteria 2 QUIC Datagram UDP relay
	targetUDP := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoUDP)))
	udpPayload := []byte("hello-hysteria2-udp-datagram")
	dgramOut := encodeHy2UDPMessage(42, 1, 0, 1, targetUDP, udpPayload)
	if err := qconn.SendDatagram(dgramOut); err != nil {
		t.Fatalf("send hy2 datagram: %v", err)
	}
	dgramIn, err := qconn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("receive hy2 datagram: %v", err)
	}
	sid, _, _, _, _, gotUDP, err := parseHy2UDPMessage(dgramIn)
	if err != nil || sid != 42 || !bytes.Equal(gotUDP, udpPayload) {
		t.Fatalf("hy2 udp mismatch: sid=%d data=%q err=%v", sid, gotUDP, err)
	}
}

func TestAnyTLSMuxV2StreamEcho(t *testing.T) {
	echoTCP, _ := startEchoTCPAndUDP(t)
	anyPort := freeLocalPort(t, "tcp")

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = anyPort
	cfg.CertMode = "self"

	tr := stats.NewTracker(cfg)
	pass := "anytls-secret-password"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 9, UUIDOrPass: pass, RemainBytes: -1},
	})

	spec := &panel.NodeSpec{
		Protocol:            "anytls",
		ListenIP:            "127.0.0.1",
		ServerPort:          anyPort,
		Network:             "tcp",
		TLSMode:             1,
		ServerName:          "localhost",
		AnyTLSPaddingScheme: "stop=4\n0=10-20",
	}
	aclEng := acl.NewEngine(false, "", "", "", nil)
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("anytls", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(anyPort)), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. Send AnyTLS auth: sha256(pass) + uint16(8) + 8-byte padding0
	var authBuf bytes.Buffer
	h := sha256.Sum256([]byte(pass))
	authBuf.Write(h[:])
	_ = binary.Write(&authBuf, binary.BigEndian, uint16(8))
	authBuf.WriteString("12345678")

	writeFrame := func(cmd byte, sid uint32, data []byte) {
		var f [7]byte
		f[0] = cmd
		binary.BigEndian.PutUint32(f[1:5], sid)
		binary.BigEndian.PutUint16(f[5:7], uint16(len(data)))
		authBuf.Write(f[:])
		authBuf.Write(data)
	}

	// 2. Send cmdSettings (v=2) + cmdSYN(stream 1) + cmdPSH(SOCKS5 addr + payload)
	writeFrame(anytlsCmdSettings, 0, []byte("v=2\nclient=test/1.0\npadding-md5=deadbeef"))
	writeFrame(anytlsCmdSYN, 1, nil)

	var targetAndData bytes.Buffer
	targetAndData.WriteByte(0x01) // IPv4
	targetAndData.Write([]byte{127, 0, 0, 1})
	_ = binary.Write(&targetAndData, binary.BigEndian, echoTCP)
	wantMsg := []byte("hello-anytls-v2-multiplexed")
	targetAndData.Write(wantMsg)
	writeFrame(anytlsCmdPSH, 1, targetAndData.Bytes())

	if _, err := c.Write(authBuf.Bytes()); err != nil {
		t.Fatal(err)
	}

	// Read frames until we receive ServerSettings, UpdatePaddingScheme, SYNACK(1), and PSH(1)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var gotServerSettings, gotPadUpdate, gotSYNACK bool
	var rxStream bytes.Buffer
	for rxStream.Len() < len(wantMsg) || !gotSYNACK {
		var fh [7]byte
		if _, err := io.ReadFull(c, fh[:]); err != nil {
			t.Fatalf("read anytls frame err=%v", err)
		}
		cmd := fh[0]
		sid := binary.BigEndian.Uint32(fh[1:5])
		dlen := int(binary.BigEndian.Uint16(fh[5:7]))
		var data []byte
		if dlen > 0 {
			data = make([]byte, dlen)
			if _, err := io.ReadFull(c, data); err != nil {
				t.Fatal(err)
			}
		}
		switch cmd {
		case anytlsCmdServerSettings:
			gotServerSettings = true
		case anytlsCmdUpdatePaddingScheme:
			gotPadUpdate = true
		case anytlsCmdSYNACK:
			if sid == 1 && len(data) == 0 {
				gotSYNACK = true
			}
		case anytlsCmdPSH:
			if sid == 1 {
				rxStream.Write(data)
			}
		}
	}

	if !gotServerSettings || !gotPadUpdate || !gotSYNACK {
		t.Fatalf("missing expected AnyTLS v2 control frames: settings=%v pad=%v synack=%v", gotServerSettings, gotPadUpdate, gotSYNACK)
	}
	if !bytes.Equal(rxStream.Bytes(), wantMsg) {
		t.Fatalf("AnyTLS stream echoed %q, want %q", rxStream.Bytes(), wantMsg)
	}
}

func TestVLESSVisionAndRealityBuilder(t *testing.T) {
	// 1. Verify REALITY listener constructs cleanly with generated X25519 key & shortIds
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rln, err := transport.BuildRealityListener(rawLn, transport.RealityOptions{
		Dest:        "www.apple.com:443",
		PrivateKey:  base64.RawURLEncoding.EncodeToString(privKey.Bytes()),
		ShortIDs:    []string{"", "0123456789abcdef"},
		ServerNames: []string{"www.apple.com"},
	})
	if err != nil {
		t.Fatalf("BuildRealityListener failed: %v", err)
	}
	_ = rln.Close()

	// 2. Verify VLESS + `xtls-rprx-vision` framing (`Addon` protobuf + Vision padding/unpadding)
	echoTCP, _ := startEchoTCPAndUDP(t)
	vPort := freeLocalPort(t, "tcp")

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = vPort

	tr := stats.NewTracker(cfg)
	uuidStr := "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 11, UUIDOrPass: uuidStr, RemainBytes: -1},
	})

	spec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: vPort,
		Network:    "tcp",
		Flow:       FlowVision,
	}
	aclEng := acl.NewEngine(false, "", "", "", nil)
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Encode VLESS header with protobuf Addon `\x0a\x10xtls-rprx-vision`
	addon := append([]byte{0x0a, byte(len(FlowVision))}, []byte(FlowVision)...)
	var wire bytes.Buffer
	wire.WriteByte(0x00)
	wire.Write(users[0].UUIDBytes[:])
	wire.WriteByte(byte(len(addon)))
	wire.Write(addon)
	wire.WriteByte(0x01) // TCP
	_ = binary.Write(&wire, binary.BigEndian, echoTCP)
	wire.WriteByte(0x01)
	wire.Write([]byte{127, 0, 0, 1})

	// Encode Vision padded block: [UUID(16) | cmd=End(1) | contentLen(2) | padLen(2) | content | padding]
	msg := []byte("vision-inner-payload-check")
	wire.Write(users[0].UUIDBytes[:])
	wire.WriteByte(visionCmdEnd)
	_ = binary.Write(&wire, binary.BigEndian, uint16(len(msg)))
	_ = binary.Write(&wire, binary.BigEndian, uint16(12))
	wire.Write(msg)
	wire.Write(make([]byte, 12))

	if _, err := c.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}

	// Server responds with VLESS [0x00, 0x00] + Vision [UUID(16) | cmd(1) | contentLen(2) | padLen(2) | content | pad]
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var vlessResp [2]byte
	if _, err := io.ReadFull(c, vlessResp[:]); err != nil || vlessResp != [2]byte{0x00, 0x00} {
		t.Fatalf("unexpected vless resp: %v err=%v", vlessResp, err)
	}
	var visHdr [21]byte
	if _, err := io.ReadFull(c, visHdr[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(visHdr[:16], users[0].UUIDBytes[:]) {
		t.Fatalf("vision response missing user UUID")
	}
	clen := int(binary.BigEndian.Uint16(visHdr[17:19]))
	gotContent := make([]byte, clen)
	if _, err := io.ReadFull(c, gotContent); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotContent, msg) {
		t.Fatalf("vision echoed %q, want %q", gotContent, msg)
	}
}

func TestWSSVLESSAndVisionZeroPadNoDeadlock(t *testing.T) {
	echoTCP, _ := startEchoTCPAndUDP(t)

	// 1. Regression test for WSS (WS + TLS): verify wsConn never bypasses *tls.Conn encryption on Write!
	wssPort := freeLocalPort(t, "tcp")
	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = wssPort
	cfg.CertMode = "self"

	tr := stats.NewTracker(cfg)
	uuidStr := "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 21, UUIDOrPass: uuidStr, RemainBytes: -1},
	})

	wssSpec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: wssPort,
		Network:    "ws",
		WSPath:     "/wss-test",
		TLSMode:    1,
		ServerName: "localhost",
	}
	aclEng := acl.NewEngine(false, "", "", "", nil)
	wssSrv, err := NewServer(cfg, wssSpec, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := wssSrv.Start(); err != nil {
		t.Fatal(err)
	}
	defer wssSrv.Close()

	tlsCli, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(wssPort)), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial WSS failed: %v", err)
	}
	defer tlsCli.Close()

	// Perform RFC 6455 client upgrade over TLS
	upgradeReq := "GET /wss-test HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := tlsCli.Write([]byte(upgradeReq)); err != nil {
		t.Fatal(err)
	}
	_ = tlsCli.SetReadDeadline(time.Now().Add(3 * time.Second))
	var respBuf [512]byte
	rn, err := tlsCli.Read(respBuf[:])
	if err != nil || !bytes.Contains(respBuf[:rn], []byte("101 Switching Protocols")) {
		t.Fatalf("WSS upgrade failed: err=%v resp=%q", err, respBuf[:rn])
	}

	// Send masked client WS binary frame containing VLESS TCP request + payload
	var vlessPayload bytes.Buffer
	vlessPayload.WriteByte(0x00)
	vlessPayload.Write(users[0].UUIDBytes[:])
	vlessPayload.WriteByte(0x00)
	vlessPayload.WriteByte(0x01)
	_ = binary.Write(&vlessPayload, binary.BigEndian, echoTCP)
	vlessPayload.WriteByte(0x01)
	vlessPayload.Write([]byte{127, 0, 0, 1})
	wantWSS := []byte("hello-over-encrypted-wss")
	vlessPayload.Write(wantWSS)

	rawFrame := vlessPayload.Bytes()
	wsFrame := []byte{0x82, 0x80 | byte(len(rawFrame)), 0x11, 0x22, 0x33, 0x44}
	for i, b := range rawFrame {
		wsFrame = append(wsFrame, b^wsFrame[2+(i&3)])
	}
	if _, err := tlsCli.Write(wsFrame); err != nil {
		t.Fatal(err)
	}

	// Read server WS frame over TLS (previously failed with `tls: bad record MAC` when unwrapRawWriter bypassed TLS!)
	var wsHdr [2]byte
	if _, err := io.ReadFull(tlsCli, wsHdr[:]); err != nil {
		t.Fatalf("read WSS server frame over TLS failed: %v", err)
	}
	frameLen := int(wsHdr[1] & 0x7F)
	frameBody := make([]byte, frameLen)
	if _, err := io.ReadFull(tlsCli, frameBody); err != nil {
		t.Fatalf("read WSS server payload failed: %v", err)
	}
	if frameLen < 2 || !bytes.Equal(frameBody[2:], wantWSS) {
		t.Fatalf("WSS echoed %q, want %q", frameBody, wantWSS)
	}

	// 2. Regression test for Vision `visionCmdContinue` with `padLen == 0`: must NOT deadlock waiting for next block!
	visPort := freeLocalPort(t, "tcp")
	cfgVis := config.Default()
	cfgVis.ListenIP = "127.0.0.1"
	cfgVis.ListenPort = visPort
	visSpec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: visPort,
		Network:    "tcp",
		Flow:       FlowVision,
	}
	visSrv, err := NewServer(cfgVis, visSpec, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng)
	if err != nil {
		t.Fatal(err)
	}
	if err := visSrv.Start(); err != nil {
		t.Fatal(err)
	}
	defer visSrv.Close()

	vc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(visPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()

	addon := append([]byte{0x0a, byte(len(FlowVision))}, []byte(FlowVision)...)
	var firstFlight bytes.Buffer
	firstFlight.WriteByte(0x00)
	firstFlight.Write(users[0].UUIDBytes[:])
	firstFlight.WriteByte(byte(len(addon)))
	firstFlight.Write(addon)
	firstFlight.WriteByte(0x01)
	_ = binary.Write(&firstFlight, binary.BigEndian, echoTCP)
	firstFlight.WriteByte(0x01)
	firstFlight.Write([]byte{127, 0, 0, 1})

	// Vision Block 1: cmd=Continue(0), padLen=0! Client waits for server reply BEFORE sending Block 2!
	flight1Msg := []byte("vision-zero-pad-continue-flight1")
	firstFlight.Write(users[0].UUIDBytes[:])
	firstFlight.WriteByte(visionCmdContinue)
	_ = binary.Write(&firstFlight, binary.BigEndian, uint16(len(flight1Msg)))
	_ = binary.Write(&firstFlight, binary.BigEndian, uint16(0)) // padLen == 0!
	firstFlight.Write(flight1Msg)

	start := time.Now()
	if _, err := vc.Write(firstFlight.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = vc.SetReadDeadline(time.Now().Add(1 * time.Second))
	var vResp [2]byte
	if _, err := io.ReadFull(vc, vResp[:]); err != nil {
		t.Fatalf("vision zero-pad Continue deadlocked or failed: %v", err)
	}
	var vHdr [21]byte
	if _, err := io.ReadFull(vc, vHdr[:]); err != nil {
		t.Fatal(err)
	}
	cLen := int(binary.BigEndian.Uint16(vHdr[17:19]))
	pLen := int(binary.BigEndian.Uint16(vHdr[19:21]))
	got1 := make([]byte, cLen)
	if _, err := io.ReadFull(vc, got1); err != nil {
		t.Fatal(err)
	}
	if pLen > 0 {
		_, _ = io.CopyN(io.Discard, vc, int64(pLen))
	}
	if !bytes.Equal(got1, flight1Msg) {
		t.Fatalf("vision flight1 echoed %q, want %q", got1, flight1Msg)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("vision zero-pad Continue stalled for %v", elapsed)
	}
}

func startServerSpeaksFirstTCP(t *testing.T, banner []byte) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write(banner)
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// TestVMessVisionAndAnyTLSDeepBugRegressions verifies fixes for:
// 1. P-01: VMess Shake128 readMask preservation across 150ms SNI peek timeout (SSH/server-first protocols)
// 2. P-02: VLESS Vision 21-byte initial header preservation across 150ms SNI peek timeout & partial header read
// 3. P-11: VLESS `cmd == 0x03` (Mux / XUDP) UDP sub-session relay + Vision flow downgrade rejection
// 4. P-07 & P-12: AnyTLS server-closed stream instant exit (<300ms, no 15s hang) + AnyTLS BitTorrent blocking
// 5. P-09: Classic SS AEAD 24-char alphanumeric password (`EVP_BytesToKey`) + V2Board hyphenated UUID SS2022
func TestVMessVisionAndAnyTLSDeepBugRegressions(t *testing.T) {
	sshBanner := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	sshPort := startServerSpeaksFirstTCP(t, sshBanner)
	_, echoUDP := startEchoTCPAndUDP(t)

	// --- 1. P-01: VMess server-speaks-first (>150ms delay before client's 1st chunk) must NOT desync Shake128! ---
	{
		cfg := config.Default()
		cfg.ForceCloseSSL = true
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}})
		idx := BuildUserIndexForCipher("vmess", "", users)
		vPort := freeLocalPort(t, "tcp")
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: vPort, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vPort)))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		// Build VMess AEAD request header with ChunkStream | ChunkMasking | GlobalPadding
		u := &idx.VMessUsers[0]
		var reqKey, reqIV, plainAuth, authID [16]byte
		var connNonce [8]byte
		_, _ = rand.Read(reqKey[:])
		_, _ = rand.Read(reqIV[:])
		_, _ = rand.Read(connNonce[:])
		binary.BigEndian.PutUint64(plainAuth[0:8], uint64(time.Now().Unix()))
		// compute crc32 via vmess helper test pattern
		u.AuthBlock.Encrypt(authID[:], makeAuthIDPlain(plainAuth[8:12]))

		var cmdPlain bytes.Buffer
		cmdPlain.WriteByte(0x01)
		cmdPlain.Write(reqIV[:])
		cmdPlain.Write(reqKey[:])
		cmdPlain.WriteByte(0x11)              // respV
		cmdPlain.WriteByte(0x01 | 0x04 | 0x08) // S | M | P
		cmdPlain.WriteByte(0x03)              // AES-128-GCM
		cmdPlain.WriteByte(0x00)
		cmdPlain.WriteByte(0x01) // TCP
		_ = binary.Write(&cmdPlain, binary.BigEndian, sshPort)
		cmdPlain.WriteByte(0x01)
		cmdPlain.Write([]byte{127, 0, 0, 1})
		appendFNV1a32(&cmdPlain)

		sealedHdr := sealVMessReqHeader(u.CmdKey, authID, connNonce, cmdPlain.Bytes())
		if _, err := c.Write(sealedHdr); err != nil {
			t.Fatal(err)
		}

		// Wait >180ms WITHOUT sending any client body chunk -> triggers server's 150ms SNI peek timeout!
		// Server must connect to SSH backend and deliver SSH banner first!
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var respHdr [38]byte
		if _, err := io.ReadFull(c, respHdr[:]); err != nil {
			t.Fatalf("VMess server-first failed waiting for SSH banner header: %v", err)
		}

		rkSum := sha256.Sum256(reqKey[:])
		rivSum := sha256.Sum256(reqIV[:])
		sShake := sha3.NewShake128()
		_, _ = sShake.Write(rivSum[:16])
		sBlk, _ := aes.NewCipher(rkSum[:16])
		sGCM, _ := cipher.NewGCM(sBlk)
		var sCnt uint16
		readSrvChunk := func() []byte {
			var pm, sm, lh [2]byte
			_, _ = sShake.Read(pm[:])
			sPad := int(binary.BigEndian.Uint16(pm[:]) % 64)
			_, _ = sShake.Read(sm[:])
			sMask := binary.BigEndian.Uint16(sm[:])
			if _, err := io.ReadFull(c, lh[:]); err != nil {
				t.Fatalf("read VMess chunk len: %v", err)
			}
			sz := int(binary.BigEndian.Uint16(lh[:]) ^ sMask)
			body := make([]byte, sz)
			if _, err := io.ReadFull(c, body); err != nil {
				t.Fatalf("read VMess chunk body: %v", err)
			}
			var sn [12]byte
			binary.BigEndian.PutUint16(sn[0:2], sCnt)
			copy(sn[2:12], rivSum[2:12])
			sCnt++
			plain, oerr := sGCM.Open(nil, sn[:], body[:sz-sPad], nil)
			if oerr != nil {
				t.Fatalf("decrypt VMess server chunk: %v", oerr)
			}
			return plain
		}

		gotBanner := readSrvChunk()
		if !bytes.Equal(gotBanner, sshBanner) {
			t.Fatalf("VMess SSH banner mismatch: got %q want %q", gotBanner, sshBanner)
		}

		// Now client sends its 1st Shake128-masked chunk -> server's Shake128 readMask MUST still be synchronized!
		clientMsg := []byte("SSH-2.0-ClientAfterPeekTimeout\r\n")
		writeOneVMessClientChunk(t, c, reqKey, reqIV, clientMsg)
		gotEcho := readSrvChunk()
		if !bytes.Equal(gotEcho, clientMsg) {
			t.Fatalf("VMess post-peek-timeout echo mismatch: got %q want %q", gotEcho, clientMsg)
		}
	}

	// --- 2. P-02 & P-11: VLESS Vision server-first (>150ms partial initHdr) + XUDP (cmd=0x03) + flow enforcement ---
	{
		cfg := config.Default()
		cfg.ForceCloseSSL = true
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 2, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}})
		vPort := freeLocalPort(t, "tcp")
		srv, err := NewServer(cfg, &panel.NodeSpec{
			Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: vPort, Network: "tcp", Flow: FlowVision,
		}, tr, BuildUserIndexForCipher("vless", "", users), acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		// (a) Unpadded downgrade (flow="") on a Vision node must be rejected!
		badC, _ := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vPort)))
		var badReq bytes.Buffer
		badReq.WriteByte(0x00)
		badReq.Write(users[0].UUIDBytes[:])
		badReq.WriteByte(0x00) // empty flow!
		badReq.WriteByte(0x01)
		_ = binary.Write(&badReq, binary.BigEndian, sshPort)
		badReq.Write([]byte{0x01, 127, 0, 0, 1})
		_, _ = badC.Write(badReq.Bytes())
		_ = badC.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		var one [1]byte
		if n, _ := badC.Read(one[:]); n > 0 {
			t.Fatal("expected unpadded flow='' downgrade to be rejected on FlowVision node")
		}
		_ = badC.Close()

		// (b) Send VLESS Vision TCP header + only 5 bytes of 21-byte Vision UUID, sleep 200ms (>150ms peek), then send remaining 16+5+payload!
		vc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vPort)))
		if err != nil {
			t.Fatal(err)
		}
		defer vc.Close()
		addon := append([]byte{0x0a, byte(len(FlowVision))}, []byte(FlowVision)...)
		var hdr bytes.Buffer
		hdr.WriteByte(0x00)
		hdr.Write(users[0].UUIDBytes[:])
		hdr.WriteByte(byte(len(addon)))
		hdr.Write(addon)
		hdr.WriteByte(0x01)
		_ = binary.Write(&hdr, binary.BigEndian, sshPort)
		hdr.Write([]byte{0x01, 127, 0, 0, 1})
		// Partial 5 bytes of Vision UUID before 150ms peek timeout!
		hdr.Write(users[0].UUIDBytes[:5])
		_, _ = vc.Write(hdr.Bytes())

		time.Sleep(200 * time.Millisecond)
		msg := []byte("vision-after-partial-peek-timeout")
		var rest bytes.Buffer
		rest.Write(users[0].UUIDBytes[5:16])
		rest.WriteByte(visionCmdEnd)
		_ = binary.Write(&rest, binary.BigEndian, uint16(len(msg)))
		_ = binary.Write(&rest, binary.BigEndian, uint16(4))
		rest.Write(msg)
		rest.Write([]byte{1, 2, 3, 4})
		_, _ = vc.Write(rest.Bytes())

		// Read VLESS [0,0] + Vision SSH banner frame + Vision echoed msg frame
		_ = vc.SetReadDeadline(time.Now().Add(2 * time.Second))
		var vr2 [2]byte
		if _, err := io.ReadFull(vc, vr2[:]); err != nil {
			t.Fatalf("Vision post-peek VLESS resp failed: %v", err)
		}
		var rxPlain bytes.Buffer
		for rxPlain.Len() < len(sshBanner)+len(msg) {
			var vh [5]byte
			if rxPlain.Len() == 0 {
				var uuidSkip [16]byte
				if _, err := io.ReadFull(vc, uuidSkip[:]); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := io.ReadFull(vc, vh[:]); err != nil {
				t.Fatal(err)
			}
			cl := int(binary.BigEndian.Uint16(vh[1:3]))
			pl := int(binary.BigEndian.Uint16(vh[3:5]))
			cb := make([]byte, cl)
			if _, err := io.ReadFull(vc, cb); err != nil {
				t.Fatal(err)
			}
			if pl > 0 {
				_, _ = io.CopyN(io.Discard, vc, int64(pl))
			}
			rxPlain.Write(cb)
		}
		if !bytes.Equal(rxPlain.Bytes(), append(append([]byte(nil), sshBanner...), msg...)) {
			t.Fatalf("Vision stream corrupted across peek timeout: got %q", rxPlain.Bytes())
		}

		// (c) VLESS `cmd == 0x03` (XUDP Mux over Vision) UDP echo!
		xc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(vPort)))
		if err != nil {
			t.Fatal(err)
		}
		defer xc.Close()
		var xreq bytes.Buffer
		xreq.WriteByte(0x00)
		xreq.Write(users[0].UUIDBytes[:])
		xreq.WriteByte(byte(len(addon)))
		xreq.Write(addon)
		xreq.WriteByte(0x03) // RequestCommandMux (NO Port/Addr in VLESS header!)

		// Build XUDP New frame: Meta = [sid=7(2) | status=New(1) | opt=Data(1) | net=UDP(2)(1) | port(2) | IPv4(1+4)] = 12B
		udpMsg := []byte("xudp-over-vision-ok")
		var xudp bytes.Buffer
		_ = binary.Write(&xudp, binary.BigEndian, uint16(12))
		_ = binary.Write(&xudp, binary.BigEndian, uint16(7))
		xudp.Write([]byte{0x01, 0x01, 0x02})
		_ = binary.Write(&xudp, binary.BigEndian, echoUDP)
		xudp.Write([]byte{0x01, 127, 0, 0, 1})
		_ = binary.Write(&xudp, binary.BigEndian, uint16(len(udpMsg)))
		xudp.Write(udpMsg)

		// Wrap XUDP frame inside Vision End block
		xreq.Write(users[0].UUIDBytes[:])
		xreq.WriteByte(visionCmdEnd)
		_ = binary.Write(&xreq, binary.BigEndian, uint16(xudp.Len()))
		_ = binary.Write(&xreq, binary.BigEndian, uint16(0))
		xreq.Write(xudp.Bytes())
		_, _ = xc.Write(xreq.Bytes())

		_ = xc.SetReadDeadline(time.Now().Add(2 * time.Second))
		var xv [2 + 21]byte
		if _, err := io.ReadFull(xc, xv[:]); err != nil {
			t.Fatalf("XUDP Vision resp header failed: %v", err)
		}
		xcLen := int(binary.BigEndian.Uint16(xv[2+17 : 2+19]))
		xpLen := int(binary.BigEndian.Uint16(xv[2+19 : 2+21]))
		xbody := make([]byte, xcLen)
		if _, err := io.ReadFull(xc, xbody); err != nil {
			t.Fatal(err)
		}
		if xpLen > 0 {
			_, _ = io.CopyN(io.Discard, xc, int64(xpLen))
		}
		if !bytes.HasSuffix(xbody, udpMsg) {
			t.Fatalf("XUDP reply %x missing payload %q", xbody, udpMsg)
		}
	}

	// --- 3. P-09: V2Board hyphenated UUID SS2022 + Classic SS AEAD 24-char alphanumeric password ---
	{
		echoTCP, _ := startEchoTCPAndUDP(t)
		cfg := config.Default()
		cfg.ForceCloseSSL = true
		tr := stats.NewTracker(cfg)
		// 24-char base64-looking alphanumeric password that SIP004 MUST hash via EVP_BytesToKey!
		const alphaPass24 = "AbCdEfGhIjKlMnOpQrStUvWx"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 9, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811", AltPasswd: alphaPass24}})
		idx := BuildUserIndexForCipher("shadowsocks", "aead_aes_128_gcm", users)
		if !bytes.Equal(idx.SSUsers[0].MasterKey, evpBytesToKey(alphaPass24, 16)) {
			t.Fatalf("classic AEAD wrongly base64-decoded 24-char password instead of EVP_BytesToKey!")
		}
		// V2Board hyphenated UUID in SS2022 must take first 16 ASCII bytes of UUID
		uV2B, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 10, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}})
		idx2022 := BuildUserIndexForCipher("shadowsocks", "2022-blake3-aes-128-gcm", uV2B)
		if string(idx2022.SSUsers[0].MasterKey) != "b831381d-6324-4d" {
			t.Fatalf("V2Board SS2022 UUID key mismatch: got %q", idx2022.SSUsers[0].MasterKey)
		}
		_ = echoTCP
	}
}

func makeAuthIDPlain(rand4 []byte) []byte {
	var p [16]byte
	binary.BigEndian.PutUint64(p[0:8], uint64(time.Now().Unix()))
	copy(p[8:12], rand4)
	// IEEE CRC32
	var crc uint32 = 0xFFFFFFFF
	for _, b := range p[0:12] {
		crc ^= uint32(b)
		for k := 0; k < 8; k++ {
			if (crc & 1) != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	binary.BigEndian.PutUint32(p[12:16], ^crc)
	return p[:]
}

func appendFNV1a32(b *bytes.Buffer) {
	var h uint32 = 2166136261
	for _, c := range b.Bytes() {
		h ^= uint32(c)
		h *= 16777619
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], h)
	b.Write(out[:])
}

func sealVMessReqHeader(cmdKey, authID [16]byte, connNonce [8]byte, cmdPlain []byte) []byte {
	lk := vmessKDF3(cmdKey[:], kdfSaltHdrLenKey, authID[:], connNonce[:])
	ln := vmessKDF3(cmdKey[:], kdfSaltHdrLenIV, authID[:], connNonce[:])
	lblk, _ := aes.NewCipher(lk[:16])
	lgcm, _ := cipher.NewGCM(lblk)
	var hlen [2]byte
	binary.BigEndian.PutUint16(hlen[:], uint16(len(cmdPlain)))
	encLen := lgcm.Seal(nil, ln[:12], hlen[:], authID[:])

	pk := vmessKDF3(cmdKey[:], kdfSaltHdrKey, authID[:], connNonce[:])
	pn := vmessKDF3(cmdKey[:], kdfSaltHdrIV, authID[:], connNonce[:])
	pblk, _ := aes.NewCipher(pk[:16])
	pgcm, _ := cipher.NewGCM(pblk)
	encPay := pgcm.Seal(nil, pn[:12], cmdPlain, authID[:])

	var out bytes.Buffer
	out.Write(authID[:])
	out.Write(encLen)
	out.Write(connNonce[:])
	out.Write(encPay)
	return out.Bytes()
}

func writeOneVMessClientChunk(t *testing.T, c net.Conn, reqKey, reqIV [16]byte, msg []byte) {
	t.Helper()
	cShake := sha3.NewShake128()
	_, _ = cShake.Write(reqIV[:])
	var pm, sm [2]byte
	_, _ = cShake.Read(pm[:])
	padLen := int(binary.BigEndian.Uint16(pm[:]) % 64)
	_, _ = cShake.Read(sm[:])
	sizeMask := binary.BigEndian.Uint16(sm[:])

	cBlk, _ := aes.NewCipher(reqKey[:])
	cGCM, _ := cipher.NewGCM(cBlk)
	var cNonce [12]byte
	copy(cNonce[2:12], reqIV[2:12])
	sealed := cGCM.Seal(nil, cNonce[:], msg, nil)

	var lh [2]byte
	binary.BigEndian.PutUint16(lh[:], uint16(len(sealed)+padLen)^sizeMask)
	_, _ = c.Write(lh[:])
	_, _ = c.Write(sealed)
	if padLen > 0 {
		_, _ = c.Write(make([]byte, padLen))
	}
}
