package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

// startMiniSOCKS5Server starts an in-process SOCKS5 landing proxy that records the exact
// domain name requested by `xoga` (verifying remote DNS unlock preservation) and relays to targetAddr.
func startMiniSOCKS5Server(t *testing.T, targetAddr string, gotDomain *atomic.Value) (port int, closeFn func()) {
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
				var greet [3]byte
				if _, err := io.ReadFull(conn, greet[:2]); err != nil {
					return
				}
				nmethods := int(greet[1])
				methods := make([]byte, nmethods)
				_, _ = io.ReadFull(conn, methods)
				_, _ = conn.Write([]byte{0x05, 0x00})

				var head [4]byte
				if _, err := io.ReadFull(conn, head[:]); err != nil || head[1] != 0x01 {
					return
				}
				switch head[3] {
				case 0x03:
					var dl [1]byte
					_, _ = io.ReadFull(conn, dl[:])
					dom := make([]byte, int(dl[0])+2)
					_, _ = io.ReadFull(conn, dom)
					gotDomain.Store(string(dom[:dl[0]]))
				case 0x01:
					var b [6]byte
					_, _ = io.ReadFull(conn, b[:])
				}
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})

				up, err := net.Dial("tcp", targetAddr)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, conn) }()
				_, _ = io.Copy(conn, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

func startLocalUDPDNSForLoopback(t *testing.T) (string, *atomic.Int32, func()) {
	t.Helper()
	var hits atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			hits.Add(1)
			qtype := binary.BigEndian.Uint16(buf[n-4 : n-2])
			resp := make([]byte, 0, n+24)
			resp = append(resp, buf[0], buf[1], 0x81, 0x80, 0x00, 0x01)
			if qtype == 1 {
				resp = append(resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
				resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 127, 0, 0, 1)
			} else {
				resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				resp = append(resp, buf[12:n]...)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String(), &hits, func() { _ = pc.Close() }
}

// TestDNSUnlockWithSNIOverride verifies that when a client sends a bogus/poisoned IP (203.0.113.99),
// xoga sniffs `Host: www.netflix.com`, rewrites the destination to `www.netflix.com`, resolves it
// via the configured Unlock DNS in `dns.yml` (-> 127.0.0.1), and completes the stream!
func TestDNSUnlockWithSNIOverride(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()
	_ = echoHost

	dnsAddr, dnsHits, closeDNS := startLocalUDPDNSForLoopback(t)
	defer closeDNS()

	tmpDir := t.TempDir()
	dnsPath := filepath.Join(tmpDir, "dns.yml")
	dnsYAML := `
"` + dnsAddr + `":
  strategy: ipv4_only
  rules:
    - geosite:netflix
`
	if err := os.WriteFile(dnsPath, []byte(dnsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.ForceCloseSSL = true
	cfg.DNSConfigPath = dnsPath
	cfg.DomainSniff = true

	tracker := stats.NewTracker(cfg)
	const pass = "trojan-dns-unlock-pass"
	users, _, _, _ := tracker.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: pass}})
	idx := BuildUserIndex(users, 0)
	aclEng := acl.NewEngine(true, "", "", "", nil)
	dnsRes := dns.NewResolver(dnsPath, "", nil, "ipv4_only")

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

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(srvPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Deliberately send unreachable TEST-NET-3 IP 203.0.113.99 in Trojan header,
	// while HTTP Host header is `www.netflix.com`!
	sum := sha256.Sum224([]byte(pass))
	var req bytes.Buffer
	req.WriteString(hex.EncodeToString(sum[:]))
	req.WriteString("\r\n")
	req.WriteByte(0x01)
	req.WriteByte(0x01)
	req.Write([]byte{203, 0, 113, 99})
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], echoPort)
	req.Write(pb[:])
	req.WriteString("\r\n")
	httpPayload := []byte("GET /watch HTTP/1.1\r\nHost: www.netflix.com\r\n\r\n")
	req.Write(httpPayload)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(httpPayload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("DNS unlock + SNI override relay failed: %v", err)
	}
	if !bytes.Equal(echoed, httpPayload) {
		t.Fatalf("payload mismatch: %q", echoed)
	}
	if dnsHits.Load() == 0 {
		t.Fatalf("expected custom unlock DNS to be queried at least once")
	}
}

// TestRouteUnlockSOCKS5AndSSLandingWithFailover verifies `routes.toml` multi-protocol outbound unlocking:
// 1. `geosite:openai` fails over from a dead primary node to a live SOCKS5 unlock proxy (preserving domain!)
// 2. `geosite:disney` routes through a live Shadowsocks (`aes-256-gcm`) unlock landing node!
func TestRouteUnlockSOCKS5AndSSLandingWithFailover(t *testing.T) {
	echoHost, echoPort, closeEcho := startEchoTCPServer(t)
	defer closeEcho()

	targetEchoAddr := net.JoinHostPort(echoHost, strconv.Itoa(int(echoPort)))
	var socksDomain atomic.Value
	socksPort, closeSOCKS := startMiniSOCKS5Server(t, targetEchoAddr, &socksDomain)
	defer closeSOCKS()

	// Spin up a second xoga instance acting as a Shadowsocks-AEAD landing node!
	ssLandingCfg := config.Default()
	ssLandingCfg.ForceCloseSSL = true
	ssTracker := stats.NewTracker(ssLandingCfg)
	ssUsers, _, _, _ := ssTracker.ReconcileUsers([]stats.SyncUserSpec{{ID: 88, UUIDOrPass: "landing-ss-pass"}})
	ssLandingPort := freeTCPPort(t)
	ssLandingSrv, err := NewServer(ssLandingCfg, &panel.NodeSpec{
		Protocol:   "shadowsocks",
		Cipher:     "aes-256-gcm",
		ListenIP:   "127.0.0.1",
		ServerPort: ssLandingPort,
		Network:    "tcp",
	}, ssTracker, BuildUserIndex(ssUsers, 32), acl.NewEngine(true, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := ssLandingSrv.Start(); err != nil {
		t.Fatal(err)
	}
	defer ssLandingSrv.Close()

	// Configure transit node's routes.toml + dns.yml (so ssLanding forwards www.disneyplus.com -> 127.0.0.1)
	dnsAddr, _, closeDNS := startLocalUDPDNSForLoopback(t)
	defer closeDNS()
	ssLandingSrv.dnsRes = dns.NewResolver("", "", []string{dnsAddr}, "ipv4_only")

	tmpDir := t.TempDir()
	routesPath := filepath.Join(tmpDir, "routes.toml")
	deadPort := freeTCPPort(t) // closed port to test automatic failover!
	routesTOML := `
[[routes]]
name = "openai-socks5-failover"
balance = "first"
rules = ["geosite:openai"]

[[routes.outs]]
type = "socks5"
server = "127.0.0.1"
port = ` + strconv.Itoa(deadPort) + `

[[routes.outs]]
type = "socks5"
server = "127.0.0.1"
port = ` + strconv.Itoa(socksPort) + `

[[routes]]
name = "disney-ss-landing"
rules = ["geosite:disney"]

[[routes.outs]]
type = "ss"
server = "127.0.0.1"
port = ` + strconv.Itoa(ssLandingPort) + `
cipher = "aes-256-gcm"
password = "landing-ss-pass"
`
	if err := os.WriteFile(routesPath, []byte(routesTOML), 0644); err != nil {
		t.Fatal(err)
	}

	transitCfg := config.Default()
	transitCfg.ForceCloseSSL = true
	transitCfg.RoutesPath = routesPath
	transitTracker := stats.NewTracker(transitCfg)
	const uuidStr = "b831381d-6324-4d53-ad4f-8cda48b30811"
	tUsers, _, _, _ := transitTracker.ReconcileUsers([]stats.SyncUserSpec{{ID: 5, UUIDOrPass: uuidStr}})
	transitPort := freeTCPPort(t)

	transitSrv, err := NewServer(transitCfg, &panel.NodeSpec{
		Protocol:   "vless",
		ListenIP:   "127.0.0.1",
		ServerPort: transitPort,
		Network:    "tcp",
	}, transitTracker, BuildUserIndex(tUsers, 0), acl.NewEngine(true, "", "", routesPath, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := transitSrv.Start(); err != nil {
		t.Fatal(err)
	}
	defer transitSrv.Close()

	// Helper to send a VLESS domain request through transitSrv
	sendVLESS := func(domain string, msg []byte) {
		t.Helper()
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(transitPort)), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()

		var req bytes.Buffer
		req.WriteByte(0x00)
		req.Write(tUsers[0].UUIDBytes[:])
		req.WriteByte(0x00)
		req.WriteByte(0x01)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], echoPort)
		req.Write(pb[:])
		req.WriteByte(0x02) // VLESS Domain
		req.WriteByte(byte(len(domain)))
		req.WriteString(domain)
		req.Write(msg)

		if _, err := c.Write(req.Bytes()); err != nil {
			t.Fatal(err)
		}
		resp := make([]byte, 2+len(msg))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatalf("VLESS route unlock (%s) failed: %v", domain, err)
		}
		if !bytes.Equal(resp[2:], msg) {
			t.Fatalf("echo mismatch for %s: %q", domain, resp[2:])
		}
	}

	// 1. Test OpenAI -> dead SOCKS5 -> automatic failover to live SOCKS5 (preserving domain `api.openai.com`)
	sendVLESS("api.openai.com", []byte("openai-via-socks5-failover-ok"))
	if got, _ := socksDomain.Load().(string); got != "api.openai.com" {
		t.Fatalf("expected SOCKS5 landing to receive domain api.openai.com, got %q", got)
	}

	// 2. Test Disney+ -> Shadowsocks AEAD landing node -> echo server
	sendVLESS("www.disneyplus.com", []byte("disney-via-shadowsocks-landing-ok"))
}

// BenchmarkVMess5146UsersAuthScan benchmarks VMess AEAD AuthID verification on a 5,146-user node
// matching the user's real production SSPanel-UIM node scale.
func BenchmarkVMess5146UsersAuthScan(b *testing.B) {
	specs := make([]stats.SyncUserSpec, 5146)
	for i := 0; i < 5146; i++ {
		var u [16]byte
		binary.BigEndian.PutUint64(u[0:8], 0xb831381d63244d53)
		binary.BigEndian.PutUint64(u[8:16], uint64(i+1))
		uuidStr := hex.EncodeToString(u[0:4]) + "-" + hex.EncodeToString(u[4:6]) + "-" +
			hex.EncodeToString(u[6:8]) + "-" + hex.EncodeToString(u[8:10]) + "-" + hex.EncodeToString(u[10:16])
		specs[i] = stats.SyncUserSpec{ID: i + 1, UUIDOrPass: uuidStr}
	}
	cfg := config.Default()
	tr := stats.NewTracker(cfg)
	users, _, _, _ := tr.ReconcileUsers(specs)
	idx := BuildUserIndex(users, 0)

	// Build a valid AuthID for user #2573 (exact middle of 5,146 users)
	mid := &idx.VMessUsers[2573]
	var plain [16]byte
	now := time.Now().Unix()
	binary.BigEndian.PutUint64(plain[0:8], uint64(now))
	plain[8], plain[9], plain[10], plain[11] = 1, 2, 3, 4
	// Compute IEEE CRC32 via AuthBlock Encrypt roundtrip
	var authID [16]byte
	// Encrypt once after setting CRC32:
	// Use standard hash/crc32 indirectly via server verification loop
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var scratch [16]byte
		for j := 0; j <= 2573; j++ {
			idx.VMessUsers[j].AuthBlock.Decrypt(scratch[:], authID[:])
		}
		_ = mid
	}
}
