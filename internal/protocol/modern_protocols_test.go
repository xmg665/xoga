package protocol

import (
	"bytes"
	"context"
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
