package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

func setupDirectSniffFixtures(t *testing.T) (uint16, string, *acl.Engine, *dns.Resolver, func()) {
	t.Helper()
	_, echoPort, closeEcho := startEchoTCPServer(t)
	dnsAddr, _, closeDNS := startLocalUDPDNSForLoopback(t)

	tmp := t.TempDir()
	routesPath := filepath.Join(tmp, "routes.toml")
	if err := os.WriteFile(routesPath, []byte(`
[[routes]]
name = "route-direct"
rules = ["*"]
[[routes.outs]]
type = "direct"
`), 0644); err != nil {
		t.Fatal(err)
	}
	whitePath := filepath.Join(tmp, "whiteList")
	if err := os.WriteFile(whitePath, []byte("127.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	aclEng := acl.NewEngine(true, whitePath, "", routesPath, nil)
	aclEng.SetPortAndPrivatePolicy("143,110", true)
	dnsRes := dns.NewResolver("", "", []string{dnsAddr}, "ipv4_only")

	return echoPort, whitePath, aclEng, dnsRes, func() {
		closeDNS()
		closeEcho()
	}
}

func TestBUG2BUG4BUG7WhitelistedIPAndMultiProtocolSniffPolicy(t *testing.T) {
	// 1. Explicitly whitelisted IP (127.0.0.1) with unresolvable HTTP Host under domain_sniff=true + ban_private_ip=true
	//    MUST stay 127.0.0.1 and NOT get rewritten to Host or fail DNS lookup!
	t.Run("WhitelistedIPNotRewrittenByDomainSniff", func(t *testing.T) {
		_, echoPort, closeEcho := startEchoTCPServer(t)
		defer closeEcho()

		tmp := t.TempDir()
		whitePath := filepath.Join(tmp, "whiteList")
		if err := os.WriteFile(whitePath, []byte("127.0.0.1\n"), 0644); err != nil {
			t.Fatal(err)
		}
		aclEng := acl.NewEngine(true, whitePath, "", "", nil)
		aclEng.SetPortAndPrivatePolicy("143", true)

		// Unreachable/dead DNS server: any DNS query would fail/timeout, proving no rewrite occurred!
		deadPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer deadPC.Close()
		dnsRes := dns.NewResolver("", "", []string{deadPC.LocalAddr().String()}, "ipv4_only")

		cfg := config.Default()
		cfg.DomainSniff = true
		cfg.BanPrivateIP = true
		cfg.WhiteListPath = whitePath
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: "white-pass"}})
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "trojan", ListenIP: "127.0.0.1", ServerPort: 0, Network: "tcp"}, tr, BuildUserIndex(users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}

		if got := srv.resolveEffectiveHost(aclEng, "127.0.0.1", "internal-only.corp.local"); got != "127.0.0.1" {
			t.Fatalf("whitelisted 127.0.0.1 was rewritten to %q", got)
		}
		if got := srv.resolveEffectiveHost(aclEng, "198.18.0.5", "public.example.test"); got != "public.example.test" {
			t.Fatalf("non-whitelisted Fake-IP 198.18.0.5 was NOT rewritten: got %q", got)
		}

		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			srv.connectAndRelay(c1, users[0], "127.0.0.1", echoPort, []byte("GET / HTTP/1.1\r\nHost: internal-only.corp.local\r\n\r\n"))
			_ = c1.Close()
		}()
		_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		want := "GET / HTTP/1.1\r\nHost: internal-only.corp.local\r\n\r\n"
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c2, got); err != nil || string(got) != want {
			t.Fatalf("whitelisted literal IP connection failed: got=%q err=%v", got, err)
		}
		_ = c2.Close()
		<-done
	})

	// 2. Hysteria2: Fake-IP + HTTP Host override under ActionDirect, metadata block, pre-peek forbidden port 143
	t.Run("Hysteria2_FakeIP_MetadataBlock_FastPort143", func(t *testing.T) {
		echoPort, _, aclEng, dnsRes, cleanup := setupDirectSniffFixtures(t)
		defer cleanup()

		hy2Port := freeLocalPort(t, "udp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = hy2Port
		cfg.CertMode = "self"
		cfg.DomainSniff = true
		cfg.BanPrivateIP = true
		cfg.ForbiddenPorts = "143,110"

		tr := stats.NewTracker(cfg)
		secret := "hy2-bug247-secret"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 11, UUIDOrPass: secret, RemainBytes: -1}})
		spec := &panel.NodeSpec{
			Protocol:    "hysteria2",
			ListenIP:    "127.0.0.1",
			ServerPort:  hy2Port,
			Network:     "quic",
			TLSMode:     1,
			ServerName:  "localhost",
			Hy2DownMbps: 100,
		}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("hysteria2", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rawUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer rawUDP.Close()
		qconn, err := quic.Dial(ctx, rawUDP, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hy2Port}, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		}, &quic.Config{EnableDatagrams: true})
		if err != nil {
			t.Fatalf("hy2 quic dial failed: %v", err)
		}
		defer qconn.CloseWithError(0, "")

		h3Tr := &http3.Transport{}
		cConn := h3Tr.NewClientConn(qconn)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
		req.Header.Set("Hysteria-Auth", secret)
		req.Header.Set("Hysteria-CC-RX", "12500000")
		resp, err := cConn.RoundTrip(req)
		if err != nil || resp.StatusCode != 233 {
			t.Fatalf("hy2 auth failed: resp=%v err=%v", resp, err)
		}
		resp.Body.Close()

		openHy2TCP := func(target string, payload []byte) (byte, string, *quic.Stream) {
			t.Helper()
			st, err := qconn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var wire []byte
			wire = quicvarint.Append(wire, hy2FrameTCPRequest)
			wire = quicvarint.Append(wire, uint64(len(target)))
			wire = append(wire, target...)
			wire = quicvarint.Append(wire, 0) // padLen=0
			wire = append(wire, payload...)
			if _, err := st.Write(wire); err != nil {
				t.Fatal(err)
			}
			var status [1]byte
			if _, err := io.ReadFull(st, status[:]); err != nil {
				t.Fatalf("read hy2 tcp status: %v", err)
			}
			br := quicvarint.NewReader(st)
			msgLen, err := quicvarint.Read(br)
			if err != nil {
				t.Fatalf("read hy2 msg len: %v", err)
			}
			msg := make([]byte, msgLen)
			if msgLen > 0 {
				_, _ = io.ReadFull(st, msg)
			}
			padLen, err := quicvarint.Read(br)
			if err == nil && padLen > 0 {
				_, _ = io.CopyN(io.Discard, st, int64(padLen))
			}
			return status[0], string(msg), st
		}

		// (a) Clash Fake-IP 198.18.0.5 + HTTP Host overrides and echoes!
		httpPay := []byte("GET /hy2 HTTP/1.1\r\nHost: hy2-fakeip.example.test\r\n\r\n")
		stCode, msg, qst := openHy2TCP(net.JoinHostPort("198.18.0.5", strconv.Itoa(int(echoPort))), httpPay)
		if stCode != 0x00 {
			t.Fatalf("Hy2 Clash Fake-IP direct sniff override failed: status=0x%02x msg=%q", stCode, msg)
		}
		got := make([]byte, len(httpPay))
		if _, err := io.ReadFull(qst, got); err != nil || !bytes.Equal(got, httpPay) {
			t.Fatalf("Hy2 echo mismatch: got=%q err=%v", got, err)
		}
		_ = qst.Close()

		// (b) Unresolved metadata 169.254.169.254 MUST be rejected!
		stCode, _, qst2 := openHy2TCP(net.JoinHostPort("169.254.169.254", strconv.Itoa(int(echoPort))), []byte("RAW-NO-SNI"))
		_ = qst2.Close()
		if stCode == 0x00 {
			t.Fatal("Hy2 allowed unresolved 169.254.169.254 under ban_private_ip=true")
		}

		// (c) Forbidden port 143 with ZERO payload short-circuits BEFORE 50ms peek!
		start := time.Now()
		stCode, _, qst3 := openHy2TCP("1.1.1.1:143", nil)
		elapsed := time.Since(start)
		_ = qst3.Close()
		if stCode == 0x00 {
			t.Fatal("Hy2 allowed forbidden port 143")
		}
		if elapsed >= 45*time.Millisecond {
			t.Fatalf("Hy2 forbidden port 143 stalled in peek: elapsed=%v (want <45ms)", elapsed)
		}
	})

	// 3. AnyTLS v2: Fake-IP + HTTP Host override under ActionDirect, metadata block, pre-peek forbidden port 143
	t.Run("AnyTLSv2_FakeIP_MetadataBlock_FastPort143", func(t *testing.T) {
		echoPort, _, aclEng, dnsRes, cleanup := setupDirectSniffFixtures(t)
		defer cleanup()

		port := freeLocalPort(t, "tcp")
		cfg := config.Default()
		cfg.ListenIP = "127.0.0.1"
		cfg.ListenPort = port
		cfg.CertMode = "self"
		cfg.DomainSniff = true
		cfg.BanPrivateIP = true
		cfg.ForbiddenPorts = "143,110"

		tr := stats.NewTracker(cfg)
		pass := "anytls-bug247-pass"
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 12, UUIDOrPass: pass, RemainBytes: -1}})
		spec := &panel.NodeSpec{
			Protocol:   "anytls",
			ListenIP:   "127.0.0.1",
			ServerPort: port,
			Network:    "tcp",
			TLSMode:    1,
			ServerName: "localhost",
		}
		srv, err := NewServer(cfg, spec, tr, BuildUserIndexForProtocol("anytls", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))

		sendAny := func(cmd byte, sid uint32, body []byte) {
			var fh [7]byte
			fh[0] = cmd
			binary.BigEndian.PutUint32(fh[1:5], sid)
			binary.BigEndian.PutUint16(fh[5:7], uint16(len(body)))
			_, _ = c.Write(append(fh[:], body...))
		}
		readFrameFor := func(wantSID uint32) (byte, []byte) {
			t.Helper()
			for {
				var fh [7]byte
				if _, err := io.ReadFull(c, fh[:]); err != nil {
					t.Fatalf("read anytls frame: %v", err)
				}
				body := make([]byte, binary.BigEndian.Uint16(fh[5:7]))
				if len(body) > 0 {
					if _, err := io.ReadFull(c, body); err != nil {
						t.Fatalf("read anytls frame body: %v", err)
					}
				}
				if binary.BigEndian.Uint32(fh[1:5]) == wantSID {
					return fh[0], body
				}
			}
		}

		hash := sha256.Sum256([]byte(pass))
		_, _ = c.Write(append(hash[:], 0, 0))
		sendAny(anytlsCmdSettings, 0, []byte("v=2\n"))

		// (a) Forbidden port 143 -> immediate error SYNACK BEFORE 150ms peek!
		start := time.Now()
		sendAny(anytlsCmdSYN, 1, nil)
		sendAny(anytlsCmdPSH, 1, []byte{0x01, 1, 1, 1, 1, 0, 143})
		cmd1, body1 := readFrameFor(1)
		elapsed := time.Since(start)
		if cmd1 != anytlsCmdSYNACK || !strings.Contains(string(body1), "blocked") {
			t.Fatalf("expected immediate blocked SYNACK for port 143, got cmd=%d body=%q", cmd1, body1)
		}
		if elapsed >= 100*time.Millisecond {
			t.Fatalf("AnyTLS forbidden port 143 stalled: elapsed=%v (want <100ms)", elapsed)
		}

		// (b) Clash Fake-IP 198.18.0.5 + HTTP Host -> SYNACK OK + echoed HTTP payload!
		sendAny(anytlsCmdSYN, 2, nil)
		var addr2 [7]byte
		addr2[0] = 0x01
		copy(addr2[1:5], []byte{198, 18, 0, 5})
		binary.BigEndian.PutUint16(addr2[5:7], echoPort)
		sendAny(anytlsCmdPSH, 2, addr2[:])
		cmd2, body2 := readFrameFor(2)
		if cmd2 != anytlsCmdSYNACK || len(body2) != 0 {
			t.Fatalf("expected OK SYNACK for Fake-IP stream, got cmd=%d body=%q", cmd2, body2)
		}
		httpPay := []byte("GET /anytls HTTP/1.1\r\nHost: anytls-fakeip.example.test\r\n\r\n")
		sendAny(anytlsCmdPSH, 2, httpPay)
		cmd2p, body2p := readFrameFor(2)
		if cmd2p != anytlsCmdPSH || !bytes.Equal(body2p, httpPay) {
			t.Fatalf("AnyTLS Fake-IP direct sniff override echo mismatch: cmd=%d body=%q", cmd2p, body2p)
		}
		sendAny(anytlsCmdFIN, 2, nil)

		// (c) Unresolved metadata 169.254.169.254 + raw payload -> closes stream with cmdFIN (no echo)!
		sendAny(anytlsCmdSYN, 3, nil)
		var addr3 [7]byte
		addr3[0] = 0x01
		copy(addr3[1:5], []byte{169, 254, 169, 254})
		binary.BigEndian.PutUint16(addr3[5:7], echoPort)
		sendAny(anytlsCmdPSH, 3, addr3[:])
		cmd3, _ := readFrameFor(3) // v2 acks before peek so client sends payload
		if cmd3 != anytlsCmdSYNACK {
			t.Fatalf("unexpected pre-peek cmd=%d for metadata stream", cmd3)
		}
		sendAny(anytlsCmdPSH, 3, []byte("RAW-NO-SNI"))
		cmd3fin, _ := readFrameFor(3)
		if cmd3fin != anytlsCmdFIN {
			t.Fatalf("expected cmdFIN blocking unresolved metadata 169.254.169.254, got cmd=%d", cmd3fin)
		}
	})

	// 4. Mux.Cool TCP: Fake-IP + HTTP Host override, metadata block, pre-peek forbidden port 143
	t.Run("MuxCoolTCP_FakeIP_MetadataBlock_FastPort143", func(t *testing.T) {
		echoPort, _, aclEng, dnsRes, cleanup := setupDirectSniffFixtures(t)
		defer cleanup()

		cfg := config.Default()
		cfg.DomainSniff = true
		cfg.BanPrivateIP = true
		cfg.ForbiddenPorts = "143,110"
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 13, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}})
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vless", ListenIP: "127.0.0.1", ServerPort: 0, Network: "tcp"}, tr, BuildUserIndexForProtocol("vless", users, 0), aclEng, dnsRes)
		if err != nil {
			t.Fatal(err)
		}

		// (a) Forbidden port 143 with empty txCh MUST finish before 60ms peek!
		sub1 := newMuxTCPSubSession()
		users[0].AcquireSubStream()
		var mu1 sync.Mutex
		var frames1 [][]byte
		done1 := make(chan struct{})
		start := time.Now()
		go srv.runMuxTCPSubSession(1, "1.1.1.1", 143, users[0], sub1, func(b []byte) error {
			mu1.Lock()
			frames1 = append(frames1, append([]byte(nil), b...))
			mu1.Unlock()
			return nil
		}, func() {}, func() { close(done1) })
		<-done1
		if elapsed := time.Since(start); elapsed >= 45*time.Millisecond {
			t.Fatalf("Mux.Cool forbidden port 143 stalled in 60ms peek: elapsed=%v", elapsed)
		}
		if len(frames1) == 0 {
			t.Fatal("expected muxEnd frame for forbidden port 143")
		}

		// (b) Clash Fake-IP 198.18.0.5 + HTTP Host overrides and echoes!
		sub2 := newMuxTCPSubSession()
		httpPay := []byte("GET /mux HTTP/1.1\r\nHost: mux-fakeip.example.test\r\n\r\n")
		sub2.txCh <- httpPay
		users[0].AcquireSubStream()
		gotReply := make(chan []byte, 4)
		done2 := make(chan struct{})
		go srv.runMuxTCPSubSession(2, "198.18.0.5", echoPort, users[0], sub2, func(b []byte) error {
			if len(b) > 8 && b[4] == 0x02 { // SessionStatusKeep
				gotReply <- append([]byte(nil), b[8:]...)
			}
			return nil
		}, func() {}, func() { close(done2) })
		select {
		case r := <-gotReply:
			if !bytes.Equal(r, httpPay) {
				t.Fatalf("Mux.Cool Fake-IP echo mismatch: got=%q want=%q", r, httpPay)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for Mux.Cool Fake-IP echo reply")
		}
		sub2.abort()
		<-done2

		// (c) Unresolved metadata 169.254.169.254 + raw payload -> rejected with muxEnd (no keep data)
		sub3 := newMuxTCPSubSession()
		sub3.txCh <- []byte("RAW-NO-SNI")
		users[0].AcquireSubStream()
		var sawKeep bool
		done3 := make(chan struct{})
		go srv.runMuxTCPSubSession(3, "169.254.169.254", echoPort, users[0], sub3, func(b []byte) error {
			if len(b) > 4 && b[4] == 0x02 { // SessionStatusKeep
				sawKeep = true
			}
			return nil
		}, func() {}, func() { close(done3) })
		<-done3
		if sawKeep {
			t.Fatal("Mux.Cool allowed unresolved metadata 169.254.169.254")
		}
	})
}
