package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

func TestNEW1WebSocketTrustedProxyCIDRsBehindProxyProtocol(t *testing.T) {
	_, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	cfg.ProxyProtocol = true
	cfg.TrustForwardedIP = false
	cfg.TrustedProxyCIDRs = []string{"203.175.12.253/32", "172.64.0.0/13"}

	tr := stats.NewTracker(cfg)
	const uuidStr = "b831381d-6324-4d53-ad4f-8cda48b30811"
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: uuidStr}})
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

	sendViaProxy := func(proxySrcIP, xffIP string) {
		t.Helper()
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))

		upgrade := "PROXY TCP4 " + proxySrcIP + " 127.0.0.1 45000 8080\r\n" +
			"GET /ws HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n" +
			"X-Forwarded-For: " + xffIP + "\r\n\r\n"
		if _, err := c.Write([]byte(upgrade)); err != nil {
			t.Fatal(err)
		}
		respBuf := make([]byte, 512)
		n, err := c.Read(respBuf)
		if err != nil || !strings.Contains(string(respBuf[:n]), "101 Switching Protocols") {
			t.Fatalf("ws upgrade failed: %q err=%v", respBuf[:n], err)
		}

		var vlessHdr bytes.Buffer
		vlessHdr.WriteByte(0x00)
		vlessHdr.Write(users[0].UUIDBytes[:])
		vlessHdr.WriteByte(0x00)
		vlessHdr.WriteByte(0x01)
		_ = binary.Write(&vlessHdr, binary.BigEndian, echoPort)
		vlessHdr.WriteByte(0x01)
		vlessHdr.Write([]byte{127, 0, 0, 1})
		vlessHdr.WriteString("hello-trusted-cidr")

		raw := vlessHdr.Bytes()
		wsFrame := make([]byte, 2+4+len(raw))
		wsFrame[0] = 0x82
		wsFrame[1] = 0x80 | byte(len(raw))
		mask := [4]byte{0x11, 0x22, 0x33, 0x44}
		copy(wsFrame[2:6], mask[:])
		for i := range raw {
			wsFrame[6+i] = raw[i] ^ mask[i&3]
		}
		if _, err := c.Write(wsFrame); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Read(respBuf); err != nil {
			t.Fatalf("echo read failed: %v", err)
		}
	}

	// 1. Trusted L7 relay 203.175.12.253 -> X-Forwarded-For 198.51.100.42 IS trusted!
	sendViaProxy("203.175.12.253", "198.51.100.42")
	alive := tr.SnapshotAliveMap()
	foundReal := false
	for _, ip := range alive[1] {
		if ip == "198.51.100.42" {
			foundReal = true
		}
		if ip == "203.175.12.253" {
			t.Fatalf("trusted L7 relay IP leaked instead of forwarded client IP: %v", alive[1])
		}
	}
	if !foundReal {
		t.Fatalf("expected tracked IP 198.51.100.42 from trusted_proxy_cidrs relay, got %v", alive[1])
	}

	// 2. Untrusted public IP 203.0.113.50 spoofing XFF 198.51.100.99 -> MUST track 203.0.113.50!
	sendViaProxy("203.0.113.50", "198.51.100.99")
	alive2 := tr.SnapshotAliveMap()
	foundUntrusted := false
	for _, ip := range alive2[1] {
		if ip == "203.0.113.50" {
			foundUntrusted = true
		}
		if ip == "198.51.100.99" {
			t.Fatalf("untrusted public peer spoofed X-Forwarded-For: %v", alive2[1])
		}
	}
	if !foundUntrusted {
		t.Fatalf("expected untrusted peer real IP 203.0.113.50, got %v", alive2[1])
	}
}

func TestBUG2BUG4BUG7DomainSniffDirectOverrideBanPrivateIPAndFastPortBlock(t *testing.T) {
	_, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	dnsAddr, dnsHits, closeDNS := startLocalUDPDNSForLoopback(t)
	defer closeDNS()

	tmp := t.TempDir()
	routesPath := filepath.Join(tmp, "routes.toml")
	// Catch-all direct route (ActionDirect) where HasRouteForDomain previously returned false!
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
	// Whitelist 127.0.0.1 ONLY so post-DNS local echo works while 169.254.169.254, 0.0.0.1, 198.18.0.5, 240.0.0.1 remain blocked!
	if err := os.WriteFile(whitePath, []byte("127.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	cfg.DomainSniff = true
	cfg.BanPrivateIP = true
	cfg.ForbiddenPorts = "143,110,25"
	cfg.RoutesPath = routesPath
	cfg.WhiteListPath = whitePath

	tracker := stats.NewTracker(cfg)
	const pass = "trojan-bug2-4-7-pass"
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: pass}})
	idx := BuildUserIndex(users, 0)
	aclEng := acl.NewEngine(true, whitePath, "", routesPath, nil)
	aclEng.SetPortAndPrivatePolicy(cfg.ForbiddenPorts, cfg.BanPrivateIP)
	// Use mock DNS as default_dns (so direct-routed sniffed domains resolve to loopback echo!)
	dnsRes := dns.NewResolver("", "", []string{dnsAddr}, "ipv4_only")

	srvPort := freeTCPPort(t)
	srv, err := NewServer(cfg, &panel.NodeSpec{
		Protocol:   "trojan",
		ListenIP:   "127.0.0.1",
		ServerPort: srvPort,
		Network:    "tcp",
	}, tracker, idx, aclEng, dnsRes)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	sendTrojan := func(atyp byte, rawAddr []byte, port uint16, payload []byte) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		sum := sha256.Sum224([]byte(pass))
		var req bytes.Buffer
		req.WriteString(hex.EncodeToString(sum[:]))
		req.WriteString("\r\n")
		req.WriteByte(0x01)
		req.WriteByte(atyp)
		req.Write(rawAddr)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], port)
		req.Write(pb[:])
		req.WriteString("\r\n")
		if len(payload) > 0 {
			req.Write(payload)
		}
		if _, err := c.Write(req.Bytes()); err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 1. BUG-2 + BUG-4: Clash Fake-IP (198.18.0.5), GFW-poisoned (0.0.0.1), and unreachable IPv6 literal (2001:db8::dead)
	//    with valid HTTP Host under ActionDirect + domain_sniff=true + ban_private_ip=true MUST override to sniffed domain and SUCCEED!
	cases := []struct {
		name    string
		atyp    byte
		rawAddr []byte
		host    string
	}{
		{"ClashFakeIP", 0x01, []byte{198, 18, 0, 5}, "fakeip-direct.example.test"},
		{"GFWZeroNet", 0x01, []byte{0, 0, 0, 1}, "gfw-zero-direct.example.test"},
		{"UnreachableIPv6Literal", 0x04, net.ParseIP("2001:db8::dead").To16(), "v6literal-direct.example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			httpPayload := []byte("GET / HTTP/1.1\r\nHost: " + tc.host + "\r\n\r\n")
			c := sendTrojan(tc.atyp, tc.rawAddr, echoPort, httpPayload)
			defer c.Close()
			got := make([]byte, len(httpPayload))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, httpPayload) {
				t.Fatalf("%s direct domain_sniff override failed: got %q err=%v", tc.name, got, err)
			}
		})
	}
	if dnsHits.Load() < 3 {
		t.Fatalf("expected mock DNS to resolve all 3 overridden domains, got %d hits", dnsHits.Load())
	}

	// 2. BUG-4: Unresolved reserved/private/Fake-IP/metadata literals (no valid non-IP SNI/Host) MUST be blocked!
	for _, blocked := range []struct {
		name    string
		rawAddr []byte
		payload []byte
	}{
		{"CloudMetadataIPHost", []byte{169, 254, 169, 254}, []byte("GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")},
		{"ZeroNetRaw", []byte{0, 0, 0, 1}, []byte("RAW-BINARY-NO-SNI")},
		{"FakeIPRaw", []byte{198, 18, 0, 9}, []byte("RAW-BINARY-NO-SNI")},
		{"ClassERaw", []byte{240, 0, 0, 1}, []byte("RAW-BINARY-NO-SNI")},
	} {
		t.Run("Blocked_"+blocked.name, func(t *testing.T) {
			c := sendTrojan(0x01, blocked.rawAddr, echoPort, blocked.payload)
			defer c.Close()
			var b [1]byte
			if n, err := c.Read(b[:]); n != 0 || err == nil {
				t.Fatalf("expected %s to be blocked by ban_private_ip, got n=%d err=%v", blocked.name, n, err)
			}
		})
	}

	// 3. BUG-7: Forbidden port (IMAP 143) with ZERO initial payload (silent server-first protocol)
	//    MUST short-circuit BEFORE 150ms peekInitialPayload!
	t.Run("ForbiddenPortShortCircuitsBefore150msPeek", func(t *testing.T) {
		start := time.Now()
		c := sendTrojan(0x01, []byte{1, 1, 1, 1}, 143, nil)
		defer c.Close()
		var b [1]byte
		n, err := c.Read(b[:])
		elapsed := time.Since(start)
		if n != 0 || err == nil {
			t.Fatalf("expected port 143 to be closed immediately, got n=%d err=%v", n, err)
		}
		if elapsed >= 100*time.Millisecond {
			t.Fatalf("forbidden port 143 stalled in peekInitialPayload: elapsed=%v (want <100ms)", elapsed)
		}
	})
}

func TestBUG5LegacyVMessWidened120sClockSkew(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	sendLegacyAtSkew := func(t *testing.T, port int, u *stats.UserEntry, skewSec int64) ([]byte, error) {
		t.Helper()
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()+skewSec))
		mac := hmac.New(md5.New, u.UUIDBytes[:])
		mac.Write(stamp[:])
		request := mac.Sum(nil)

		key := md5.Sum(append(u.UUIDBytes[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
		iv := md5.Sum(bytes.Repeat(stamp[:], 4))
		block, _ := aes.NewCipher(key[:])

		header := make([]byte, 42)
		header[0] = 1
		_, _ = rand.Read(header[1:33])
		header[33] = 4
		header[35], header[37], header[40], header[41] = 5, 1, 2, byte(len(echoHost))
		binary.BigEndian.PutUint16(header[38:40], echoPort)
		header = append(header, echoHost...)
		sum := fnv.New32a()
		sum.Write(header)
		header = sum.Sum(header)
		reqKey, reqIV := [16]byte(header[17:33]), [16]byte(header[1:17])
		respKey := md5.Sum(reqKey[:])
		respIV := md5.Sum(reqIV[:])
		cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header, header)

		payload := []byte("skew-ok")
		request = append(append(request, header...), payload...)

		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(request); err != nil {
			return nil, err
		}
		resp := make([]byte, 4+len(payload))
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, err
		}
		rblk, _ := aes.NewCipher(respKey[:])
		cipher.NewCFBDecrypter(rblk, respIV[:]).XORKeyStream(resp[:4], resp[:4])
		if resp[0] != 4 {
			return nil, io.ErrUnexpectedEOF
		}
		return resp[4:], nil
	}

	// 1. Auto mode (shared legacyRing): +81s and -115s accepted, +125s rejected!
	t.Run("AutoModeAccepts81sAnd115sSkew", func(t *testing.T) {
		cfg := config.Default()
		cfg.VMessAuthMode = "auto"
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
			{ID: 7001, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		})
		idx := BuildUserIndexForProtocol("vmess", users, 0)
		port := freeTCPPort(t)
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		for _, skew := range []int64{81, -115} {
			got, err := sendLegacyAtSkew(t, port, users[0], skew)
			if err != nil || string(got) != "skew-ok" {
				t.Fatalf("auto mode rejected legacy client at skew=%+ds: got=%q err=%v", skew, got, err)
			}
		}
		if got, err := sendLegacyAtSkew(t, port, users[0], 125); err == nil {
			t.Fatalf("auto mode accepted legacy client beyond ±120s window: %q", got)
		}
	})

	// 2. Explicit vmess_legacy_users (aead mode): +81s and -100s accepted!
	t.Run("ExplicitLegacyUsersAccepts81sSkew", func(t *testing.T) {
		cfg := config.Default()
		cfg.ApplyKV("vmess_auth_mode", "aead")
		cfg.ApplyKV("vmess_legacy_users", "7002:0")
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
			{ID: 7002, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"},
		})
		idx := BuildUserIndexForProtocol("vmess", users, 0)
		port := freeTCPPort(t)
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		for _, skew := range []int64{81, -100} {
			got, err := sendLegacyAtSkew(t, port, users[0], skew)
			if err != nil || string(got) != "skew-ok" {
				t.Fatalf("explicit vmess_legacy_users rejected client at skew=%+ds: got=%q err=%v", skew, got, err)
			}
		}
	})
}

func TestBUG11BindErrorNotDoubleWrapped(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	tr := stats.NewTracker(cfg)
	srv, err := NewServer(cfg, &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: port,
		Network:    "tcp",
	}, tr, BuildUserIndexForProtocol("vless", nil, 0), acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	startErr := srv.Start()
	if startErr == nil {
		srv.Close()
		t.Fatal("expected bind failure on occupied port")
	}
	if strings.Count(startErr.Error(), "listen tcp") != 1 {
		t.Fatalf("bind error must not double-wrap 'listen tcp': %v", startErr)
	}
}

func TestBUG12VMessHandshakeRejectionWireMetadata(t *testing.T) {
	cfg := config.Default()
	cfg.VMessAuthMode = "auto"
	tr := stats.NewTracker(cfg)
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
		{ID: 42, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
	})
	idx := BuildUserIndexForProtocol("vmess", users, 0)
	srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: 0, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	srv.legacy.refresh(idx, now)

	// 1. read_authid includes byte count and io.EOF / ErrUnexpectedEOF
	t.Run("ReadAuthID", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() {
			_, _ = c2.Write([]byte{1, 2, 3})
			_ = c2.Close()
		}()
		_, _, _, _, _, reason := srv.handshakeVMess(c1)
		if !strings.Contains(reason, "read_authid") || !strings.Contains(reason, "n=3") || !strings.Contains(reason, "EOF") {
			t.Fatalf("expected rich read_authid metadata, got %q", reason)
		}
	})

	// 2. legacy_header includes user ID and underlying error
	t.Run("LegacyHeader", func(t *testing.T) {
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(now))
		auth := hmacMD5Stamp(users[0].UUIDBytes, stamp)

		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() {
			_, _ = c2.Write(auth[:])
			_ = c2.Close()
		}()
		_, _, _, _, _, reason := srv.handshakeVMess(c1)
		if !strings.Contains(reason, "legacy_header") || !strings.Contains(reason, "user=42") || !strings.Contains(reason, "EOF") {
			t.Fatalf("expected rich legacy_header metadata, got %q", reason)
		}
	})

	// 3. header_checksum includes legacy, user, ver, cmd, hdrLen
	t.Run("HeaderChecksum", func(t *testing.T) {
		badHdr := make([]byte, 46)
		badHdr[0] = 0x02  // wrong version
		badHdr[37] = 0x01 // TCP cmd
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		_, _, _, _, _, reason := srv.finishVMessHandshake(c1, c1, &idx.VMessUsers[0], badHdr, true)
		for _, want := range []string{"header_checksum", "legacy=true", "user=42", "ver=0x02", "cmd=0x01", "hdrLen=46"} {
			if !strings.Contains(reason, want) {
				t.Fatalf("header_checksum reason %q missing %q", reason, want)
			}
		}
	})

	// 4. header_decrypt includes legacy=false, user, hdrLen, and AEAD err
	t.Run("HeaderDecrypt", func(t *testing.T) {
		var authPlain [16]byte
		binary.BigEndian.PutUint64(authPlain[:8], uint64(now))
		binary.BigEndian.PutUint32(authPlain[12:16], crc32IEEE(authPlain[:12]))
		var authID [16]byte
		idx.VMessBlocks[0].Encrypt(authID[:], authPlain[:])

		connNonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
		lenKey := vmessKDF3(idx.VMessUsers[0].CmdKey[:], kdfSaltHdrLenKey, authID[:], connNonce[:])
		lenNonce := vmessKDF3(idx.VMessUsers[0].CmdKey[:], kdfSaltHdrLenIV, authID[:], connNonce[:])
		lenBlk, _ := aes.NewCipher(lenKey[:16])
		lenGCM, _ := cipher.NewGCM(lenBlk)
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], 42)
		encLen := lenGCM.Seal(nil, lenNonce[:12], lb[:], authID[:])
		badEncHdr := make([]byte, 42+16) // invalid ciphertext/tag

		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() {
			var wire bytes.Buffer
			wire.Write(authID[:])
			wire.Write(encLen)
			wire.Write(connNonce[:])
			wire.Write(badEncHdr)
			_, _ = c2.Write(wire.Bytes())
			_ = c2.Close()
		}()
		_, _, _, _, _, reason := srv.handshakeVMess(c1)
		for _, want := range []string{"header_decrypt", "legacy=false", "user=42", "hdrLen=58"} {
			if !strings.Contains(reason, want) {
				t.Fatalf("header_decrypt reason %q missing %q", reason, want)
			}
		}
	})
}

func crc32IEEE(b []byte) uint32 {
	var crc uint32 = 0xFFFFFFFF
	for _, v := range b {
		crc ^= uint32(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func TestLegacyVMessAutoSkipAndExplicitHeaderError(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	// 1. Explicit vmess_legacy_users in aead mode: matched user with truncated header MUST report
	//    `legacy_header user=<id>` (NOT fall through to `auth_no_user_match`)!
	t.Run("ExplicitLegacyHeaderErrorSurfaced", func(t *testing.T) {
		cfg := config.Default()
		cfg.ApplyKV("vmess_auth_mode", "aead")
		cfg.ApplyKV("vmess_legacy_users", "42:1")
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
			{ID: 42, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		})
		idx := BuildUserIndexForProtocol("vmess", users, 0)
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: 0, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}

		// Use alterID #1 so we also exercise alterID path
		altUUID := nextVMessAlterID(users[0].UUIDBytes)
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()))
		auth := hmacMD5Stamp(altUUID, stamp)

		c1, c2 := net.Pipe()
		defer c1.Close()
		go func() {
			_, _ = c2.Write(auth[:])
			_ = c2.Close()
		}()
		_, _, _, _, _, reason := srv.handshakeVMess(c1)
		if !strings.Contains(reason, "legacy_header") || !strings.Contains(reason, "user=42") || !strings.Contains(reason, "EOF") {
			t.Fatalf("expected legacy_header error for matched vmess_legacy_users entry, got %q", reason)
		}
	})

	// 2. Auto mode + vmess_legacy_users with alterID=1: primary UUID (n=0) succeeds via O(1) ring,
	//    alterID (n=1) STILL succeeds via readLegacyVMessHeader even though n=0 is skipped,
	//    and unmatched probes when alterID=0 short-circuit without redundant n=0 HMAC scans!
	t.Run("AutoModeSkipsRedundantPrimaryScanWhilePreservingAlterID", func(t *testing.T) {
		cfg := config.Default()
		cfg.ApplyKV("vmess_auth_mode", "auto")
		cfg.ApplyKV("vmess_legacy_users", "501:0,502:1")
		tr := stats.NewTracker(cfg)
		users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{
			{ID: 501, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"},
			{ID: 502, UUIDOrPass: "75eae340-a037-4cc2-b64c-ae5dc26cc897"},
		})
		idx := BuildUserIndexForProtocol("vmess", users, 0)
		port := freeTCPPort(t)
		srv, err := NewServer(cfg, &panel.NodeSpec{Protocol: "vmess", ListenIP: "127.0.0.1", ServerPort: port, Network: "tcp"}, tr, idx, acl.NewEngine(false, "", "", "", nil))
		if err != nil {
			t.Fatal(err)
		}
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer srv.Close()

		// Send alterID #1 request for user 502
		altID := nextVMessAlterID(users[1].UUIDBytes)
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()))
		auth := hmacMD5Stamp(altID, stamp)
		key := md5.Sum(append(users[1].UUIDBytes[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
		iv := md5.Sum(bytes.Repeat(stamp[:], 4))
		block, _ := aes.NewCipher(key[:])

		header := make([]byte, 42)
		header[0] = 1
		_, _ = rand.Read(header[1:33])
		header[33] = 7
		header[35], header[37], header[40], header[41] = 5, 1, 2, byte(len(echoHost))
		binary.BigEndian.PutUint16(header[38:40], echoPort)
		header = append(header, echoHost...)
		sum := fnv.New32a()
		sum.Write(header)
		header = sum.Sum(header)
		reqKey, reqIV := [16]byte(header[17:33]), [16]byte(header[1:17])
		respKey := md5.Sum(reqKey[:])
		respIV := md5.Sum(reqIV[:])
		cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header, header)

		payload := []byte("alterid-ok")
		req := append(append(auth[:], header...), payload...)
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write(req); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, 4+len(payload))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatalf("alterID=1 legacy handshake under auto mode failed: %v", err)
		}
		rblk, _ := aes.NewCipher(respKey[:])
		cipher.NewCFBDecrypter(rblk, respIV[:]).XORKeyStream(resp[:4], resp[:4])
		if resp[0] != 7 || string(resp[4:]) != "alterid-ok" {
			t.Fatalf("unexpected alterID=1 response: v=%d payload=%q", resp[0], resp[4:])
		}
	})
}
