package protocol

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/sha3"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/sniff"
	"github.com/xmg665/xoga/internal/stats"
)

func TestC2SharedLegacyAuthPerNodeIsolationAndZeroAllocHMAC(t *testing.T) {
	// 1. Verify stack hmacMD5Stamp matches stdlib crypto/hmac bit-for-bit.
	var key [16]byte
	var stamp [8]byte
	_, _ = rand.Read(key[:])
	binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()))
	got := hmacMD5Stamp(key, stamp)
	mac := hmac.New(md5.New, key[:])
	_, _ = mac.Write(stamp[:])
	var want [16]byte
	copy(want[:], mac.Sum(nil))
	if got != want {
		t.Fatalf("hmacMD5Stamp mismatch: got %x want %x", got, want)
	}

	// 2. Verify two nodes sharing the process-wide global legacy cache enforce strict
	//    per-node UserIndex membership (User 1 on Node A must NOT authenticate on Node B).
	cfg := config.Default()
	trA := stats.NewTracker(cfg)
	trB := stats.NewTracker(cfg)
	usersA, _, _, _ := trA.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{ID: 3, UUIDOrPass: "11111111-2222-3333-4444-555555555555"},
	})
	usersB, _, _, _ := trB.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 2, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"},
		{ID: 3, UUIDOrPass: "11111111-2222-3333-4444-555555555555"},
	})
	idxA := BuildUserIndexForProtocol("vmess", usersA, 0)
	idxB := BuildUserIndexForProtocol("vmess", usersB, 0)

	var cacheA, cacheB legacyAuthCache
	cacheA.start(func() *UserIndex { return idxA })
	defer cacheA.close()
	cacheB.start(func() *UserIndex { return idxB })
	defer cacheB.close()

	now := time.Now().Unix()
	var st [8]byte
	binary.BigEndian.PutUint64(st[:], uint64(now))

	authU1 := hmacMD5Stamp(usersA[0].UUIDBytes, st)
	authU2 := hmacMD5Stamp(usersB[0].UUIDBytes, st)
	authShared := hmacMD5Stamp(usersA[1].UUIDBytes, st)

	// User 1 belongs ONLY to Node A
	if e, _, ok := cacheA.lookupIn(idxA, authU1); !ok || e.User.ID != 1 {
		t.Fatalf("Node A should match User 1, got ok=%v", ok)
	}
	if _, _, ok := cacheB.lookupIn(idxB, authU1); ok {
		t.Fatal("Node B must NOT match User 1 (belongs only to Node A)")
	}
	// User 2 belongs ONLY to Node B
	if e, _, ok := cacheB.lookupIn(idxB, authU2); !ok || e.User.ID != 2 {
		t.Fatalf("Node B should match User 2, got ok=%v", ok)
	}
	if _, _, ok := cacheA.lookupIn(idxA, authU2); ok {
		t.Fatal("Node A must NOT match User 2 (belongs only to Node B)")
	}
	// Shared User 3 matches on both nodes with each node's own entry
	if eA, _, ok := cacheA.lookupIn(idxA, authShared); !ok || eA.User != usersA[1] {
		t.Fatal("Node A should match shared User 3 with Node A's UserEntry")
	}
	if eB, _, ok := cacheB.lookupIn(idxB, authShared); !ok || eB.User != usersB[1] {
		t.Fatal("Node B should match shared User 3 with Node B's UserEntry")
	}

	// Incremental user addition & removal on Node A via sync()
	usersA2, _, _, _ := trA.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 4, UUIDOrPass: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
	})
	idxA2 := BuildUserIndexForProtocol("vmess", usersA2, 0)
	cacheA.sync(idxA2)

	authU4 := hmacMD5Stamp(usersA2[0].UUIDBytes, st)
	if e, _, ok := cacheA.lookupIn(idxA2, authU4); !ok || e.User.ID != 4 {
		t.Fatal("incremental sync failed to add User 4")
	}
	if _, _, ok := cacheA.lookupIn(idxA2, authU1); ok {
		t.Fatal("removed User 1 must not match on Node A after sync")
	}
}

func TestH6VMessLegacyCFBAndNoneGlobalPadEOFAndAuthLenReject(t *testing.T) {
	var reqKey, reqIV [16]byte
	_, _ = rand.Read(reqKey[:])
	_, _ = rand.Read(reqIV[:])

	// 1. RequestOptionAuthenticatedLength (opt & 0x10) must be cleanly rejected
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := newVMessStreamConn(c1, c1, reqKey, reqIV, 0x01, 0x15, 0x03, false, false); err == nil {
		t.Fatal("expected RequestOptionAuthenticatedLength (0x10) to be rejected cleanly")
	}

	// 2. AES-128-CFB with opt=0x05 (ChunkStream|ChunkMasking) accepts size==0 EOF
	t.Run("CFB_NoGlobalPad_SizeZeroEOF", func(t *testing.T) {
		srvC, cliC := net.Pipe()
		defer srvC.Close()
		defer cliC.Close()

		vc, err := newVMessStreamConn(srvC, srvC, reqKey, reqIV, 0x11, 0x05, 0x01, false, false)
		if err != nil {
			t.Fatal(err)
		}
		defer vc.releaseReadBuf()

		go func() {
			reqBlk, _ := aes.NewCipher(reqKey[:])
			cfb := cipher.NewCFBEncrypter(reqBlk, reqIV[:])
			sh := sha3.NewShake128()
			_, _ = sh.Write(reqIV[:])
			var mb [2]byte
			_, _ = sh.Read(mb[:])
			// Bare 2-byte masked size=0 EOF chunk
			var eofWire [2]byte
			binary.BigEndian.PutUint16(eofWire[:], 0^binary.BigEndian.Uint16(mb[:]))
			cfb.XORKeyStream(eofWire[:], eofWire[:])
			_, _ = cliC.Write(eofWire[:])
		}()

		var buf [64]byte
		_ = vc.SetReadDeadline(time.Now().Add(time.Second))
		n, err := vc.Read(buf[:])
		if n != 0 || err != io.EOF {
			t.Fatalf("expected io.EOF for CFB size==0 EOF chunk, got n=%d err=%v", n, err)
		}
	})

	// 3. AES-128-CFB with optGlobalPad (0x0d) accepts bare 2-byte size==padLen EOF without hanging,
	//    and FlushResponseHeader emits bare 2-byte masked padLen (no 4B FNV1a32).
	t.Run("CFB_GlobalPad_SizePadLenEOF_And_ServerFlush", func(t *testing.T) {
		srvC, cliC := net.Pipe()
		defer srvC.Close()
		defer cliC.Close()

		vc, err := newVMessStreamConn(srvC, srvC, reqKey, reqIV, 0x22, 0x0d, 0x01, false, false)
		if err != nil {
			t.Fatal(err)
		}
		defer vc.releaseReadBuf()

		// Client writes bare 2-byte size==padLen EOF (no FNV, no trailing pad bytes)
		go func() {
			reqBlk, _ := aes.NewCipher(reqKey[:])
			cfb := cipher.NewCFBEncrypter(reqBlk, reqIV[:])
			sh := sha3.NewShake128()
			_, _ = sh.Write(reqIV[:])
			var pb, mb [2]byte
			_, _ = sh.Read(pb[:])
			_, _ = sh.Read(mb[:])
			padLen := binary.BigEndian.Uint16(pb[:]) % 64
			var eofWire [2]byte
			binary.BigEndian.PutUint16(eofWire[:], padLen^binary.BigEndian.Uint16(mb[:]))
			cfb.XORKeyStream(eofWire[:], eofWire[:])
			_, _ = cliC.Write(eofWire[:])
		}()

		var buf [64]byte
		_ = vc.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := vc.Read(buf[:]); n != 0 || err != io.EOF {
			t.Fatalf("expected io.EOF for CFB+GlobalPad size==padLen EOF, got n=%d err=%v", n, err)
		}

		// Server FlushResponseHeader should emit 38B AEAD resp header + EXACTLY 2B CFB EOF length (no 4B FNV!)
		errCh := make(chan error, 1)
		go func() {
			errCh <- vc.FlushResponseHeader()
		}()
		_ = cliC.SetReadDeadline(time.Now().Add(time.Second))
		var respBytes [40]byte
		if _, err := io.ReadFull(cliC, respBytes[:]); err != nil {
			t.Fatalf("read server resp+EOF failed: %v", err)
		}
		if err := <-errCh; err != nil {
			t.Fatalf("FlushResponseHeader failed: %v", err)
		}
		rk := sha256.Sum256(reqKey[:])
		riv := sha256.Sum256(reqIV[:])
		respBlk, _ := aes.NewCipher(rk[:16])
		cfbDec := cipher.NewCFBDecrypter(respBlk, riv[:16])
		var decSize [2]byte
		cfbDec.XORKeyStream(decSize[:], respBytes[38:40])
		wsh := sha3.NewShake128()
		_, _ = wsh.Write(riv[:16])
		var wpb, wmb [2]byte
		_, _ = wsh.Read(wpb[:])
		_, _ = wsh.Read(wmb[:])
		wantPad := binary.BigEndian.Uint16(wpb[:]) % 64
		gotSize := binary.BigEndian.Uint16(decSize[:]) ^ binary.BigEndian.Uint16(wmb[:])
		if gotSize != wantPad {
			t.Fatalf("server CFB EOF size=%d want padLen=%d (must NOT include 4B FNV)", gotSize, wantPad)
		}
	})

	// 4. SecurityTypeNone (0x05) with optGlobalPad (0x0d) must NOT hang on bare 2-byte size==padLen EOF
	t.Run("None_GlobalPad_NoHangOnEOF", func(t *testing.T) {
		srvC, cliC := net.Pipe()
		defer srvC.Close()
		defer cliC.Close()

		vc, err := newVMessStreamConn(srvC, srvC, reqKey, reqIV, 0x33, 0x0d, 0x05, false, false)
		if err != nil {
			t.Fatal(err)
		}
		defer vc.releaseReadBuf()

		go func() {
			sh := sha3.NewShake128()
			_, _ = sh.Write(reqIV[:])
			var pb, mb [2]byte
			_, _ = sh.Read(pb[:])
			_, _ = sh.Read(mb[:])
			padLen := binary.BigEndian.Uint16(pb[:]) % 64
			if padLen == 0 {
				// Even if padLen happened to be 0, test still verifies clean EOF
			}
			var eofWire [2]byte
			binary.BigEndian.PutUint16(eofWire[:], padLen^binary.BigEndian.Uint16(mb[:]))
			_, _ = cliC.Write(eofWire[:])
		}()

		var buf [64]byte
		_ = vc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := vc.Read(buf[:])
		if n != 0 || err != io.EOF {
			t.Fatalf("SecurityTypeNone+optGlobalPad hung or failed on EOF: n=%d err=%v", n, err)
		}
	})
}

func TestM1AnyTLSServerSettingsOrderAndCmdAlertFlush(t *testing.T) {
	echoTCP, _ := startEchoTCPAndUDP(t)
	anyPort := freeLocalPort(t, "tcp")

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = anyPort
	cfg.CertMode = "self"

	tr := stats.NewTracker(cfg)
	pass := "anytls-m1-order-secret"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 11, UUIDOrPass: pass, RemainBytes: -1}})
	spec := &panel.NodeSpec{
		Protocol:   "anytls",
		ListenIP:   "127.0.0.1",
		ServerPort: anyPort,
		Network:    "tcp",
		TLSMode:    1,
		ServerName: "localhost",
	}
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("anytls", users, 0), acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// 1. Send cmdSettings(v=2) + cmdSYN + cmdPSH in ONE write -> first server frame MUST be cmdServerSettings!
	c1, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(anyPort)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))

	hash := sha256.Sum256([]byte(pass))
	var req bytes.Buffer
	req.Write(hash[:])
	req.Write([]byte{0, 0}) // pad0=0
	// cmdSettings v=2
	settingsBody := []byte("v=2\n")
	var fh [7]byte
	fh[0] = anytlsCmdSettings
	binary.BigEndian.PutUint16(fh[5:7], uint16(len(settingsBody)))
	req.Write(fh[:])
	req.Write(settingsBody)
	// cmdSYN sid=1
	fh[0] = anytlsCmdSYN
	binary.BigEndian.PutUint32(fh[1:5], 1)
	binary.BigEndian.PutUint16(fh[5:7], 0)
	req.Write(fh[:])
	// cmdPSH sid=1 SOCKS5 addr 127.0.0.1:echoTCP
	var addrBuf bytes.Buffer
	addrBuf.WriteByte(0x01)
	addrBuf.Write([]byte{127, 0, 0, 1})
	_ = binary.Write(&addrBuf, binary.BigEndian, echoTCP)
	fh[0] = anytlsCmdPSH
	binary.BigEndian.PutUint32(fh[1:5], 1)
	binary.BigEndian.PutUint16(fh[5:7], uint16(addrBuf.Len()))
	req.Write(fh[:])
	req.Write(addrBuf.Bytes())

	if _, err := c1.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	var rfh [7]byte
	if _, err := io.ReadFull(c1, rfh[:]); err != nil {
		t.Fatalf("read first AnyTLS server frame failed: %v", err)
	}
	if rfh[0] != anytlsCmdServerSettings {
		t.Fatalf("expected first server frame to be cmdServerSettings (%d), got %d (raced behind cmdSYNACK!)", anytlsCmdServerSettings, rfh[0])
	}
	dlen := int(binary.BigEndian.Uint16(rfh[5:7]))
	body := make([]byte, dlen)
	if _, err := io.ReadFull(c1, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != "v=2" {
		t.Fatalf("unexpected cmdServerSettings body %q", body)
	}

	// 2. Send cmdSYN WITHOUT cmdSettings -> client MUST receive cmdAlert before EOF!
	c2, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(anyPort)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(3 * time.Second))

	var req2 bytes.Buffer
	req2.Write(hash[:])
	req2.Write([]byte{0, 0})
	fh[0] = anytlsCmdSYN
	binary.BigEndian.PutUint32(fh[1:5], 9)
	binary.BigEndian.PutUint16(fh[5:7], 0)
	req2.Write(fh[:])
	if _, err := c2.Write(req2.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c2, rfh[:]); err != nil {
		t.Fatalf("expected cmdAlert before close, got read error: %v", err)
	}
	if rfh[0] != anytlsCmdAlert {
		t.Fatalf("expected cmdAlert (%d), got %d", anytlsCmdAlert, rfh[0])
	}
}

func TestN2M5H7Hysteria2ObfsNoneDialErrorAndDomainUDPReply(t *testing.T) {
	_, echoUDP := startEchoTCPAndUDP(t)
	hy2Port := freeLocalPort(t, "udp")

	// Start local UDP DNS resolving "echo.hy2.local" -> 127.0.0.1
	dnsAddr, _, closeDNS := startLocalUDPDNSForLoopback(t)
	defer closeDNS()

	cfg := config.Default()
	cfg.ListenIP = "127.0.0.1"
	cfg.ListenPort = hy2Port
	cfg.CertMode = "self"
	tr := stats.NewTracker(cfg)
	secret := "hy2-n2-m5-secret"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 15, UUIDOrPass: secret, RemainBytes: -1}})

	// H7: Hy2Obfs="none" must be normalized to "" and start cleanly without error
	spec := &panel.NodeSpec{
		Protocol:   "hysteria2",
		ListenIP:   "127.0.0.1",
		ServerPort: hy2Port,
		Network:    "quic",
		TLSMode:    1,
		ServerName: "localhost",
		Hy2Obfs:    "none",
	}
	dnsRes := dns.NewResolver("", "", []string{dnsAddr}, "ipv4_only")
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("hysteria2", users, 0), acl.NewEngine(false, "", "", "", nil), dnsRes)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Hysteria2 with obfs=none failed to start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(hy2Port)), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "")

	h3Tr := &http3.Transport{EnableDatagrams: false}
	cConn := h3Tr.NewClientConn(qconn)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	req.Header.Set("Hysteria-Auth", secret)
	resp, err := cConn.RoundTrip(req)
	if err != nil || resp.StatusCode != 233 {
		t.Fatalf("hy2 auth failed: resp=%v err=%v", resp, err)
	}
	resp.Body.Close()

	// N2: Dialing a closed local port MUST return TCPResponse status=0x01 (error), NOT 0x00 OK!
	closedPort := freeLocalPort(t, "tcp")
	qstr, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	targetClosed := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(closedPort)))
	var tcpReq []byte
	tcpReq = quicvarint.Append(tcpReq, hy2FrameTCPRequest)
	tcpReq = quicvarint.Append(tcpReq, uint64(len(targetClosed)))
	tcpReq = append(tcpReq, targetClosed...)
	tcpReq = quicvarint.Append(tcpReq, 0)
	if _, err := qstr.Write(tcpReq); err != nil {
		t.Fatal(err)
	}
	var stByte [1]byte
	if _, err := io.ReadFull(qstr, stByte[:]); err != nil {
		t.Fatalf("read TCPResponse status failed: %v", err)
	}
	if stByte[0] != 0x01 {
		t.Fatalf("expected Hy2 TCPResponse status=0x01 on dial failure, got 0x%02x", stByte[0])
	}
	_ = qstr.Close()

	// M5: UDP datagram sent to domain "echo.hy2.local:<echoUDP>" must receive reply with addr "echo.hy2.local:<echoUDP>"!
	origDomainAddr := net.JoinHostPort("echo.hy2.local", strconv.Itoa(int(echoUDP)))
	payload := []byte("hy2-domain-udp-reply")
	if err := qconn.SendDatagram(encodeHy2UDPMessage(77, 1, 0, 1, origDomainAddr, payload)); err != nil {
		t.Fatal(err)
	}
	dgramIn, err := qconn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sid, _, _, _, replyAddr, gotPayload, err := parseHy2UDPMessage(dgramIn)
	if err != nil || sid != 77 || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("hy2 udp echo failed: sid=%d data=%q err=%v", sid, gotPayload, err)
	}
	if replyAddr != origDomainAddr {
		t.Fatalf("expected Hy2 UDP reply addr=%q (original domain), got %q", origDomainAddr, replyAddr)
	}
}

func TestM6PeekInitialPayloadPQClientHelloAndH4WriteUoTAddrAndM9EmptyCredGuard(t *testing.T) {
	// H4: writeUoTAddr must safely reject nil *net.UDPAddr and nil IP without corrupting buffer
	var buf bytes.Buffer
	if writeUoTAddr(&buf, nil) || buf.Len() != 0 {
		t.Fatal("writeUoTAddr(nil) must return false and write nothing")
	}
	if writeUoTAddr(&buf, &net.UDPAddr{Port: 53}) || buf.Len() != 0 {
		t.Fatal("writeUoTAddr(nil IP) must return false and write nothing")
	}

	// M9 + N12: BuildUserIndex must skip empty credentials and deduplicate duplicate user IDs
	emptyU := stats.NewUserEntry(99, "", 0, 0, 0, false)
	validU := stats.NewUserEntry(100, "b831381d-6324-4d53-ad4f-8cda48b30811", 0, 0, 0, false)
	idx := BuildUserIndex([]*stats.UserEntry{emptyU, validU, validU}, 32)
	if len(idx.ByTrojan) != 1 || len(idx.BySHA256) != 1 || len(idx.SSUsers) != 1 || len(idx.VMessUsers) != 1 {
		t.Fatalf("expected empty cred skipped and duplicate ID deduped: trojan=%d sha256=%d ss=%d vmess=%d",
			len(idx.ByTrojan), len(idx.BySHA256), len(idx.SSUsers), len(idx.VMessUsers))
	}

	// M6: peekInitialPayload reassembles >2 KiB PQ TLS ClientHello split across 5 chunks
	sni := "pq-mlkem.example.com"
	ch := buildLargePQClientHello(sni, 2600)
	srvC, cliC := net.Pipe()
	defer srvC.Close()
	defer cliC.Close()
	go func() {
		// Split across 5 chunks
		splits := []int{5, 500, 1200, 2000, len(ch)}
		prev := 0
		for _, end := range splits {
			_, _ = cliC.Write(ch[prev:end])
			prev = end
			time.Sleep(5 * time.Millisecond)
		}
	}()
	srv := &Server{}
	peeked, err := srv.peekInitialPayload(srvC)
	if err != nil {
		t.Fatalf("peekInitialPayload failed: %v", err)
	}
	if len(peeked) != len(ch) {
		t.Fatalf("expected full %dB PQ ClientHello, got %dB", len(ch), len(peeked))
	}
	sn := sniff.Inspect(peeked)
	if !strings.EqualFold(sn.Domain, sni) {
		t.Fatalf("expected sniffed SNI %q from 2.6 KiB PQ ClientHello, got %q", sni, sn.Domain)
	}
}

func buildLargePQClientHello(sni string, padExtLen int) []byte {
	// Build a valid TLS 1.3 ClientHello with a large dummy PQ key_share extension BEFORE SNI
	var exts bytes.Buffer
	// Dummy padding/key_share extension (type 0x0033) of padExtLen bytes
	_ = binary.Write(&exts, binary.BigEndian, uint16(0x0033))
	_ = binary.Write(&exts, binary.BigEndian, uint16(padExtLen))
	exts.Write(make([]byte, padExtLen))
	// SNI extension (type 0x0000) placed AFTER the large PQ key_share!
	sniEntryLen := 1 + 2 + len(sni)
	sniListLen := 2 + sniEntryLen
	_ = binary.Write(&exts, binary.BigEndian, uint16(0x0000))
	_ = binary.Write(&exts, binary.BigEndian, uint16(sniListLen))
	_ = binary.Write(&exts, binary.BigEndian, uint16(sniEntryLen))
	exts.WriteByte(0x00)
	_ = binary.Write(&exts, binary.BigEndian, uint16(len(sni)))
	exts.WriteString(sni)

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // TLS 1.2 legacy version
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0)              // session_id len
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})
	_ = binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	bLen := body.Len()
	hs.Write([]byte{byte(bLen >> 16), byte(bLen >> 8), byte(bLen)})
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.Write([]byte{0x16, 0x03, 0x01})
	_ = binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestH2WebSocketIgnoresSpoofedForwardedHeadersBehindProxyProtocol(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()
	_ = echoHost

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	cfg.ProxyProtocol = true
	cfg.TrustForwardedIP = false
	cfg.DeviceLimitEnable = true
	cfg.UserConnLimit = 1

	tr := stats.NewTracker(cfg)
	const uuidStr = "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 1, UUIDOrPass: uuidStr, DeviceLimit: 1},
	})
	srvPort := freeTCPPort(t)
	spec := &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "ws",
		WSPath:     "/ws",
	}
	srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("vless", users, 0), acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Connect through simulated L4 relay sending PROXY v1 header with public IP 203.0.113.50,
	// while client attempts to spoof CF-Connecting-IP: 198.51.100.99!
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	upgrade := "PROXY TCP4 203.0.113.50 127.0.0.1 45000 8080\r\n" +
		"GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"CF-Connecting-IP: 198.51.100.99\r\n" +
		"X-Forwarded-For: 198.51.100.98\r\n\r\n"
	if _, err := c.Write([]byte(upgrade)); err != nil {
		t.Fatal(err)
	}
	respBuf := make([]byte, 512)
	n, err := c.Read(respBuf)
	if err != nil || !strings.Contains(string(respBuf[:n]), "101 Switching Protocols") {
		t.Fatalf("ws upgrade failed: %q err=%v", respBuf[:n], err)
	}

	// Send masked WS frame carrying VLESS TCP header to echoPort
	var vlessHdr bytes.Buffer
	vlessHdr.WriteByte(0x00)
	vlessHdr.Write(users[0].UUIDBytes[:])
	vlessHdr.WriteByte(0x00) // addon len
	vlessHdr.WriteByte(0x01) // TCP
	_ = binary.Write(&vlessHdr, binary.BigEndian, echoPort)
	vlessHdr.WriteByte(0x01)
	vlessHdr.Write([]byte{127, 0, 0, 1})
	vlessHdr.WriteString("hello-pp-ws")

	raw := vlessHdr.Bytes()
	wsFrame := make([]byte, 2+4+len(raw))
	wsFrame[0] = 0x82
	wsFrame[1] = 0x80 | byte(len(raw))
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	copy(wsFrame[2:6], mask[:])
	for i := range raw {
		wsFrame[6+i] = raw[i] ^ mask[i&3]
	}
	if _, err := c.Write(wsFrame); err != nil {
		t.Fatal(err)
	}
	// Read WS reply (wait briefly for session registration)
	if _, err := c.Read(respBuf); err != nil {
		t.Fatalf("ws vless echo read failed: %v", err)
	}

	alive := tr.SnapshotAliveMap()
	ips := alive[1]
	if len(ips) != 1 || ips[0] != "203.0.113.50" {
		t.Fatalf("expected tracked client IP to be real PROXY IP 203.0.113.50 (ignoring spoofed CF-Connecting-IP), got %v", ips)
	}
	// Verify netip parse sanity
	if netip.MustParseAddr(ips[0]) != netip.MustParseAddr("203.0.113.50") {
		t.Fatalf("unexpected IP %v", ips)
	}
}
