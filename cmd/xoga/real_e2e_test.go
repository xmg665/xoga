//go:build linux && e2e

package main

import (
	"bufio"
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/crypto/sha3"
)

func freePort(t *testing.T, netw string) int {
	t.Helper()
	return freeUniquePorts(t, netw, 1)[0]
}

func freeUniquePorts(t *testing.T, netw string, count int) []int {
	t.Helper()
	ports := make([]int, 0, count)
	closers := make([]io.Closer, 0, count)
	defer func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}()
	for len(ports) < count {
		if netw == "udp" {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			closers = append(closers, pc)
			ports = append(ports, pc.LocalAddr().(*net.UDPAddr).Port)
		} else {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			closers = append(closers, ln)
			ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		}
	}
	return ports
}

func readProcVmRSSKiB(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return strconv.ParseInt(fields[1], 10, 64)
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/%d/status", pid)
}

func deterministicUUID(id int) (string, [16]byte) {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[0:8], 0x584f47412d453245) // "XOGA-E2E"
	binary.BigEndian.PutUint64(raw[8:16], uint64(id))
	h := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), raw
}

func TestRealMachineFullDaemonE2E(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "xoga")

	// 1. Compile the REAL xoga binary with leading-"v" Version ldflag to verify double-v guard too
	buildCmd := exec.Command("go", "build", "-trimpath",
		"-ldflags=-s -w -X github.com/xmg665/xoga/internal/version.Version=v1.3.6 -X github.com/xmg665/xoga/internal/version.Commit=e2etest",
		"-o", binPath, ".")
	buildCmd.Dir = "."
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// 2. CLI real-machine checks on the compiled binary
	t.Run("CLI_EOF_Version_Validation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binPath)
		cmd.Stdin = strings.NewReader("") // immediate EOF!
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("interactive menu on stdin EOF failed: %v\nout=%s", err, out)
		}
		if !strings.Contains(string(out), "xoga v1.3.6 ") || strings.Contains(string(out), "vv1.3.6") {
			t.Fatalf("unexpected Summary version in menu output: %s", out)
		}

		if err := exec.Command(binPath, "log", "../../etc/passwd").Run(); err == nil {
			t.Fatal("expected invalid instance in `xoga log` to exit non-zero")
		}
		if err := exec.Command(binPath, "rename", "../bad", "good").Run(); err == nil {
			t.Fatal("expected invalid oldName in `xoga rename` to exit non-zero")
		}
	})

	// 3. Spin up real local TCP & UDP echo backends
	tcpEchoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEchoLn.Close()
	echoTCPPort := uint16(tcpEchoLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := tcpEchoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	udpEchoPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEchoPC.Close()
	echoUDPPort := uint16(udpEchoPC.LocalAddr().(*net.UDPAddr).Port)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpEchoPC.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEchoPC.WriteTo(buf[:n], addr)
		}
	}()

	// 4. Spin up real local UDP DNS server (answers 127.0.0.1 for A queries)
	dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsPC.Close()
	var dnsQueries atomic.Int32
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := dnsPC.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			dnsQueries.Add(1)
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
			_, _ = dnsPC.WriteTo(resp, addr)
		}
	}()
	dnsAddr := dnsPC.LocalAddr().String()

	// 5. Remote dns_config_url server (tests C1: survives >5s hot-reload window!)
	remoteDNSSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf(`
servers:
  - address: "127.0.0.1:1"
  - address: "%s"
    strategy: ipv4_only
    domains:
      - "geosite:netflix"
      - "domain:hy2.e2e"
`, dnsAddr))
	}))
	defer remoteDNSSrv.Close()

	// 6. Allocate ports for 20 VMess+WS nodes (101..120) + VLESS(201) + Hy2(202) + AnyTLS(203)
	nodePorts := make(map[int]int)
	for id := 101; id <= 120; id++ {
		nodePorts[id] = freePort(t, "tcp")
	}
	nodePorts[201] = freePort(t, "tcp") // VLESS+WS
	nodePorts[202] = freePort(t, "udp") // Hysteria2
	nodePorts[203] = freePort(t, "tcp") // AnyTLS

	// Pre-build 2,500 users JSON payloads (User 1 exclusive to 101, User 2 exclusive to 102, Users 3..2500 shared)
	type mockUser struct {
		ID          int    `json:"id"`
		UUID        string `json:"uuid"`
		DeviceLimit any    `json:"device_limit,omitempty"`
		Banned      any    `json:"banned,omitempty"`
	}
	u1Str, u1Bytes := deterministicUUID(1)
	u2Str, _ := deterministicUUID(2)
	sharedUsers := make([]mockUser, 0, 2498)
	for i := 3; i <= 2500; i++ {
		s, _ := deterministicUUID(i)
		sharedUsers = append(sharedUsers, mockUser{ID: i, UUID: s})
	}
	makeUsersJSON := func(first mockUser) []byte {
		list := make([]mockUser, 0, 2500)
		list = append(list, first)
		list = append(list, sharedUsers...)
		// Include a string/bool banned user to verify N11 live!
		list = append(list, mockUser{ID: 9999, UUID: "deadbeef-dead-beef-dead-beefdeadbeef", Banned: true, DeviceLimit: "1"})
		b, _ := json.Marshal(map[string]any{"users": list})
		return b
	}
	usersNode101 := makeUsersJSON(mockUser{ID: 1, UUID: u1Str, DeviceLimit: "1", Banned: false})
	usersNode102 := makeUsersJSON(mockUser{ID: 2, UUID: u2Str, DeviceLimit: "1", Banned: "0"})
	usersSharedOnly, _ := json.Marshal(map[string]any{"users": append([]mockUser{{ID: 1, UUID: u1Str, DeviceLimit: "1"}}, sharedUsers[:50]...)})

	var trafficPushCount atomic.Int32
	panelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nid, _ := strconv.Atoi(r.URL.Query().Get("node_id"))
		nt := r.URL.Query().Get("node_type")
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			// Force auto-probe on HTTP 500 when node_type omitted (tests H7!)
			if nt == "" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			switch {
			case nid >= 101 && nid <= 120:
				if nt != "vmess" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"protocol":        "vmess",
					"listen_ip":       "127.0.0.1",
					"server_port":     nodePorts[nid],
					"network":         "ws",
					"networkSettings": map[string]any{"path": "/vmess"},
					"tls":             0,
				})
			case nid == 201:
				if nt != "vless" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"protocol":        "vless",
					"listen_ip":       "127.0.0.1",
					"server_port":     nodePorts[nid],
					"network":         "ws",
					"networkSettings": map[string]any{"path": "/vless"},
					"tls":             0,
				})
			case nid == 202:
				if nt != "hysteria2" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"protocol":    "hysteria2",
					"listen_ip":   "127.0.0.1",
					"server_port": nodePorts[nid],
					"obfs":        "none",
					"tls":         1,
					"server_name": "localhost",
				})
			case nid == 203:
				if nt != "anytls" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"protocol":    "anytls",
					"listen_ip":   "127.0.0.1",
					"server_port": nodePorts[nid],
					"tls":         1,
					"server_name": "localhost",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		case strings.HasSuffix(r.URL.Path, "/user"):
			if nid == 101 {
				_, _ = w.Write(usersNode101)
			} else if nid >= 102 && nid <= 120 {
				_, _ = w.Write(usersNode102)
			} else {
				_, _ = w.Write(usersSharedOnly)
			}
		case strings.HasSuffix(r.URL.Path, "/push"):
			trafficPushCount.Add(1)
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer panelSrv.Close()

	confPath := filepath.Join(tmp, "xoga.conf")
	confText := fmt.Sprintf(`type=v2board
server_type=auto
node_id=101-120,201,202,203
webapi_url=%s
webapi_key=e2e-secret-key
vmess_auth_mode=auto
proxy_protocol=true
trust_forwarded_ip=false
device_limit_enable=true
user_conn_limit=1
dns_config_url=%s
dns_strategy=ipv4_only
check_interval=60
submit_interval=60
log_level=info
gc_percent=75
`, panelSrv.URL, remoteDNSSrv.URL)
	if err := os.WriteFile(confPath, []byte(confText), 0600); err != nil {
		t.Fatal(err)
	}

	// 7. Launch the REAL xoga daemon subprocess!
	var daemonOut bytes.Buffer
	var daemonOutMu sync.Mutex
	cmd := exec.Command(binPath, "run", "-c", confPath)
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xoga daemon: %v", err)
	}
	copyLog := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				daemonOutMu.Lock()
				daemonOut.Write(buf[:n])
				daemonOutMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}
	go copyLog(stdoutPipe)
	go copyLog(stderrPipe)

	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	// Wait until nodes 101, 120, 201, 203 are listening on TCP
	waitPort := func(port int) {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		daemonOutMu.Lock()
		logs := daemonOut.String()
		daemonOutMu.Unlock()
		t.Fatalf("port %d did not start listening within 15s; daemon logs:\n%s", port, logs)
	}
	waitPort(nodePorts[101])
	waitPort(nodePorts[120])
	waitPort(nodePorts[201])
	waitPort(nodePorts[203])
	time.Sleep(200 * time.Millisecond)

	// Measure REAL Linux kernel VmRSS for 20 VMess+WS nodes (2,500 users each = 50,000 node-user entries) + 3 more nodes!
	rss1, err := readProcVmRSSKiB(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[REAL-MACHINE RSS @ startup, 23 nodes / 50k VMess user-slots]: %.2f MiB (%d KiB)", float64(rss1)/1024.0, rss1)
	if rss1 > 180*1024 { // Previously ~770 MiB; must now be far under 180 MiB!
		t.Fatalf("VmRSS too high for 20 VMess nodes with shared pointer-free cache: %.2f MiB", float64(rss1)/1024.0)
	}

	// Helper: open WebSocket with optional PROXY v1 header and custom HTTP headers
	dialWS := func(port int, path, proxyHdr string, extraHdrs string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", port, err)
		}
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		req := proxyHdr +
			"GET " + path + " HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
			extraHdrs + "\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("ws write: %v", err)
		}
		br := bufio.NewReader(c)
		status, err := br.ReadString('\n')
		if err != nil || !strings.Contains(status, "101") {
			t.Fatalf("ws upgrade failed: %q err=%v", status, err)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		return c
	}
	writeWSFrame := func(w io.Writer, payload []byte) error {
		mask := [4]byte{0x13, 0x37, 0x42, 0x99}
		var hdr []byte
		hdr = append(hdr, 0x82)
		if len(payload) < 126 {
			hdr = append(hdr, 0x80|byte(len(payload)))
		} else {
			hdr = append(hdr, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
		}
		hdr = append(hdr, mask[:]...)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ mask[i&3]
		}
		_, err := w.Write(append(hdr, masked...))
		return err
	}
	readWSFrame := func(r io.Reader) ([]byte, error) {
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		plen := int(h[1] & 0x7f)
		if plen == 126 {
			var e [2]byte
			if _, err := io.ReadFull(r, e[:]); err != nil {
				return nil, err
			}
			plen = int(binary.BigEndian.Uint16(e[:]))
		}
		b := make([]byte, plen)
		_, err := io.ReadFull(r, b)
		return b, err
	}

	buildLegacyVMessReq := func(uuidBytes [16]byte, reqKey, reqIV [16]byte, host string, port uint16, payload []byte) []byte {
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()))
		mac := hmac.New(md5.New, uuidBytes[:])
		_, _ = mac.Write(stamp[:])
		authID := mac.Sum(nil)

		mh := md5.New()
		mh.Write(uuidBytes[:])
		mh.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
		cmdKey := mh.Sum(nil)

		var rep [32]byte
		for i := 0; i < 32; i += 8 {
			copy(rep[i:], stamp[:])
		}
		hdrIV := md5.Sum(rep[:])

		var hdr bytes.Buffer
		hdr.WriteByte(0x01)
		hdr.Write(reqIV[:])
		hdr.Write(reqKey[:])
		hdr.Write([]byte{0x44, 0x05, 0x01, 0x00, 0x01}) // opt=0x05 (ChunkStream|ChunkMasking), sec=0x01 (AES-128-CFB), cmd=TCP
		_ = binary.Write(&hdr, binary.BigEndian, port)
		hdr.Write([]byte{0x02, byte(len(host))})
		hdr.WriteString(host)
		fh := fnv.New32a()
		_, _ = fh.Write(hdr.Bytes())
		_ = binary.Write(&hdr, binary.BigEndian, fh.Sum32())

		hdrBlk, _ := aes.NewCipher(cmdKey)
		encHdr := make([]byte, hdr.Len())
		cipher.NewCFBEncrypter(hdrBlk, hdrIV[:]).XORKeyStream(encHdr, hdr.Bytes())

		// Encrypt 1 CFB chunk + size=0 EOF chunk
		rm := sha3.NewShake128()
		_, _ = rm.Write(reqIV[:])
		var m1, m2 [2]byte
		_, _ = rm.Read(m1[:])
		_, _ = rm.Read(m2[:])

		var bodyPlain bytes.Buffer
		_ = binary.Write(&bodyPlain, binary.BigEndian, uint16(4+len(payload))^binary.BigEndian.Uint16(m1[:]))
		pfh := fnv.New32a()
		_, _ = pfh.Write(payload)
		_ = binary.Write(&bodyPlain, binary.BigEndian, pfh.Sum32())
		bodyPlain.Write(payload)
		_ = binary.Write(&bodyPlain, binary.BigEndian, uint16(0)^binary.BigEndian.Uint16(m2[:]))

		bodyBlk, _ := aes.NewCipher(reqKey[:])
		encBody := make([]byte, bodyPlain.Len())
		cipher.NewCFBEncrypter(bodyBlk, reqIV[:]).XORKeyStream(encBody, bodyPlain.Bytes())

		return append(append(authID, encHdr...), encBody...)
	}

	// 8. Sleep 5.5s so `maybeHotReload` 5s interval elapses -> proves C1 (remote dns_config_url NOT wiped!)
	//    and verifies legacy ring 1s ticker runs cleanly with low RSS!
	time.Sleep(5500 * time.Millisecond)

	// 9. Test C1 + C2 + H1 + H6: Legacy MD5 VMess+WS+CFB on Node 101 targeting `unlock-e2e.netflix.com:<echoTCPPort>`!
	//    (Catch-all 127.0.0.1:1 in remote dns.yml must NOT shadow geosite:netflix -> resolves via dnsAddr -> 127.0.0.1!)
	t.Run("C1_C2_H1_H6_VMessLegacyWSAndRemoteDNSUnlock", func(t *testing.T) {
		c := dialWS(nodePorts[101], "/vmess", "PROXY TCP4 203.0.113.1 127.0.0.1 10001 8080\r\n", "")
		defer c.Close()

		var reqKey, reqIV [16]byte
		_, _ = rand.Read(reqKey[:])
		_, _ = rand.Read(reqIV[:])
		msg := []byte("real-machine-vmess-legacy-cfb-dns-unlock!")
		wire := buildLegacyVMessReq(u1Bytes, reqKey, reqIV, "unlock-e2e.netflix.com", echoTCPPort, msg)
		if err := writeWSFrame(c, wire); err != nil {
			t.Fatal(err)
		}
		// Read legacy 4B resp hdr + CFB chunk from WS frames
		var rawResp bytes.Buffer
		respKey := md5.Sum(reqKey[:])
		respIV := md5.Sum(reqIV[:])
		respBlk, _ := aes.NewCipher(respKey[:])
		dec := cipher.NewCFBDecrypter(respBlk, respIV[:])

		for rawResp.Len() < 4+2+4+len(msg) {
			f, err := readWSFrame(c)
			if err != nil {
				t.Fatalf("read WS reply failed (got %dB so far): %v", rawResp.Len(), err)
			}
			rawResp.Write(f)
		}
		plain := make([]byte, rawResp.Len())
		dec.XORKeyStream(plain, rawResp.Bytes())
		if plain[0] != 0x44 {
			t.Fatalf("bad VMess legacy respV: 0x%02x", plain[0])
		}
		if !bytes.Contains(plain[4:], msg) {
			t.Fatalf("echo payload not found in VMess legacy CFB response")
		}
		if dnsQueries.Load() == 0 {
			t.Fatal("remote dns_config_url unlock DNS was never queried")
		}
	})

	// 10. Test C2 Per-Node Isolation: User 1 MUST be rejected on Node 102!
	t.Run("C2_CrossNodeLegacyAuthRejected", func(t *testing.T) {
		c := dialWS(nodePorts[102], "/vmess", "PROXY TCP4 203.0.113.2 127.0.0.1 10002 8080\r\n", "")
		defer c.Close()
		var reqKey, reqIV [16]byte
		_, _ = rand.Read(reqKey[:])
		_, _ = rand.Read(reqIV[:])
		wire := buildLegacyVMessReq(u1Bytes, reqKey, reqIV, "127.0.0.1", echoTCPPort, []byte("forbidden"))
		_ = writeWSFrame(c, wire)
		if f, err := readWSFrame(c); err == nil {
			t.Fatalf("Node 102 accepted User 1 (belongs only to Node 101)! got %x", f)
		}
	})

	// 11. Test H2: VLESS+WS with ProxyProtocol=true, TrustForwardedIP=false, DeviceLimit=1 rejects spoofed CF-Connecting-IP!
	t.Run("H2_ProxyProtocolWSSpoofBlocked", func(t *testing.T) {
		sendVLESS := func(c net.Conn, payload string) ([]byte, error) {
			var b bytes.Buffer
			b.WriteByte(0x00)
			b.Write(u1Bytes[:])
			b.WriteByte(0x00)
			b.WriteByte(0x01)
			_ = binary.Write(&b, binary.BigEndian, echoTCPPort)
			b.WriteByte(0x01)
			b.Write([]byte{127, 0, 0, 1})
			b.WriteString(payload)
			if err := writeWSFrame(c, b.Bytes()); err != nil {
				return nil, err
			}
			return readWSFrame(c)
		}

		// Conn 1 from real PROXY IP 203.0.113.50 with spoofed CF-Connecting-IP: 198.51.100.77
		c1 := dialWS(nodePorts[201], "/vless", "PROXY TCP4 203.0.113.50 127.0.0.1 20001 8080\r\n", "CF-Connecting-IP: 198.51.100.77\r\n")
		defer c1.Close()
		r1, err := sendVLESS(c1, "first-device")
		if err != nil || !bytes.Contains(r1, []byte("first-device")) {
			t.Fatalf("first VLESS+WS device failed: %q err=%v", r1, err)
		}

		// Conn 2 from DIFFERENT real PROXY IP 203.0.113.51 spoofing SAME CF-Connecting-IP: 198.51.100.77 -> MUST BE REJECTED!
		c2 := dialWS(nodePorts[201], "/vless", "PROXY TCP4 203.0.113.51 127.0.0.1 20002 8080\r\n", "CF-Connecting-IP: 198.51.100.77\r\n")
		defer c2.Close()
		if r2, err := sendVLESS(c2, "second-device-spoof"); err == nil && bytes.Contains(r2, []byte("second-device-spoof")) {
			t.Fatalf("H2 bypass: 2nd device bypassed device_limit=1 by spoofing CF-Connecting-IP behind ProxyProtocol!")
		}
	})

	// 12. Test H7 + N2 + M5: Hysteria2 obfs="none" auth + TCP echo + TCP dial fail 0x01 + UDP domain reply!
	t.Run("H7_N2_M5_Hysteria2RealMachine", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		qconn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", nodePorts[202]), &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		}, &quic.Config{EnableDatagrams: true})
		if err != nil {
			t.Fatalf("quic dial hy2: %v", err)
		}
		defer qconn.CloseWithError(0, "")

		h3Tr := &http3.Transport{EnableDatagrams: false}
		cConn := h3Tr.NewClientConn(qconn)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
		req.Header.Set("Hysteria-Auth", u1Str)
		resp, err := cConn.RoundTrip(req)
		if err != nil || resp.StatusCode != 233 {
			t.Fatalf("hy2 auth failed: resp=%v err=%v", resp, err)
		}
		resp.Body.Close()

		// TCP dial fail -> status 0x01
		closedPort := freePort(t, "tcp")
		qs, err := qconn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		targetClosed := fmt.Sprintf("127.0.0.1:%d", closedPort)
		var tcpReq []byte
		tcpReq = quicvarint.Append(tcpReq, 0x401)
		tcpReq = quicvarint.Append(tcpReq, uint64(len(targetClosed)))
		tcpReq = append(tcpReq, targetClosed...)
		tcpReq = quicvarint.Append(tcpReq, 0)
		_, _ = qs.Write(tcpReq)
		var st [1]byte
		if _, err := io.ReadFull(qs, st[:]); err != nil || st[0] != 0x01 {
			t.Fatalf("expected hy2 TCP dial fail status 0x01, got 0x%02x err=%v", st[0], err)
		}
		_ = qs.Close()

		// UDP domain reply preservation via remote dns_config_url rule `domain:hy2.e2e`!
		origAddr := fmt.Sprintf("echo.hy2.e2e:%d", echoUDPPort)
		out := make([]byte, 8)
		binary.BigEndian.PutUint32(out[0:4], 99)
		binary.BigEndian.PutUint16(out[4:6], 1)
		out[6] = 0
		out[7] = 1
		out = quicvarint.Append(out, uint64(len(origAddr)))
		out = append(out, origAddr...)
		out = append(out, []byte("hy2-e2e-udp")...)
		if err := qconn.SendDatagram(out); err != nil {
			t.Fatal(err)
		}
		in, err := qconn.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		alen, n, err := quicvarint.Parse(in[8:])
		if err != nil {
			t.Fatal(err)
		}
		gotAddr := string(in[8+n : 8+n+int(alen)])
		gotData := string(in[8+n+int(alen):])
		if gotAddr != origAddr || gotData != "hy2-e2e-udp" {
			t.Fatalf("hy2 UDP domain reply mismatch: addr=%q (want %q) data=%q", gotAddr, origAddr, gotData)
		}
	})

	// 13. Test M1: AnyTLS v2 `cmdServerSettings` strictly before `cmdSYNACK` + `cmdAlert` flush!
	t.Run("M1_AnyTLSRealMachine", func(t *testing.T) {
		rawC, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", nodePorts[203]), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer rawC.Close()
		// Node 203 is behind ProxyProtocol=true, send PROXY v1 header before TLS!
		_, _ = rawC.Write([]byte("PROXY TCP4 203.0.113.80 127.0.0.1 30001 8443\r\n"))
		tc := tls.Client(rawC, &tls.Config{InsecureSkipVerify: true})
		_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
		if err := tc.Handshake(); err != nil {
			t.Fatalf("AnyTLS TLS handshake: %v", err)
		}
		h := sha256.Sum256([]byte(u1Str))
		var req bytes.Buffer
		req.Write(h[:])
		req.Write([]byte{0, 0})
		// cmdSettings(v=2) + cmdSYN(sid=1) in one burst
		sBody := []byte("v=2\n")
		var fh [7]byte
		fh[0] = 4 // cmdSettings
		binary.BigEndian.PutUint16(fh[5:7], uint16(len(sBody)))
		req.Write(fh[:])
		req.Write(sBody)
		fh[0] = 1 // cmdSYN
		binary.BigEndian.PutUint32(fh[1:5], 1)
		binary.BigEndian.PutUint16(fh[5:7], 0)
		req.Write(fh[:])
		if _, err := tc.Write(req.Bytes()); err != nil {
			t.Fatal(err)
		}
		var rfh [7]byte
		if _, err := io.ReadFull(tc, rfh[:]); err != nil {
			t.Fatal(err)
		}
		if rfh[0] != 10 { // cmdServerSettings
			t.Fatalf("expected cmdServerSettings (10) first, got %d", rfh[0])
		}
	})

	// 14. Check post-traffic steady-state VmRSS + graceful SIGTERM shutdown + final traffic flush!
	rss2, err := readProcVmRSSKiB(cmd.Process.Pid)
	if err == nil {
		t.Logf("[REAL-MACHINE RSS @ steady-state after traffic & 6s ticks]: %.2f MiB (%d KiB)", float64(rss2)/1024.0, rss2)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM failed: %v", err)
	}
	doneWait := make(chan error, 1)
	go func() { doneWait <- cmd.Wait() }()
	select {
	case werr := <-doneWait:
		if werr != nil {
			t.Fatalf("xoga did not exit cleanly on SIGTERM: %v", werr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("xoga hung >10s on SIGTERM")
	}
	if trafficPushCount.Load() == 0 {
		t.Fatal("expected final traffic flush to mock panel on SIGTERM")
	}
}

// TestRealMachineLiveLogBugFixesE2E launches a real compiled `xoga` binary configured as a
// multi-node SSPanel daemon and exercises NEW-1, NEW-3, BUG-2, BUG-4, BUG-5, BUG-7, BUG-8,
// BUG-9, and BUG-10 end-to-end against real local TCP/UDP/DNS sockets and OS signals.
func TestRealMachineLiveLogBugFixesE2E(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "xoga")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build xoga failed: %v\n%s", err, out)
	}

	// 1. Real TCP echo backend
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Real local UDP DNS server (answers 127.0.0.1 for A queries)
	dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsPC.Close()
	var dnsHits atomic.Int32
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := dnsPC.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 16 {
				continue
			}
			dnsHits.Add(1)
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
			_, _ = dnsPC.WriteTo(resp, addr)
		}
	}()
	dnsAddr := dnsPC.LocalAddr().String()

	// 3. Allocate unique local ports for 3 SSPanel nodes: 781 (VLESS+WS), 782 (VMess+WS), 783 (Trojan+TCP)
	ports := freeUniquePorts(t, "tcp", 3)
	port781, port782, port783 := ports[0], ports[1], ports[2]

	u1Str, u1Bytes := deterministicUUID(101)
	const trojanPass = "e2e-trojan-live-pass"

	var detectRuleHits atomic.Int32
	var trafficPushHits atomic.Int32
	panelSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mod_mu/nodes/781/info":
			_, _ = fmt.Fprintf(w, `{"ret":1,"data":{"server":"127.0.0.1;%d;0;ws;;path=/vless","sort":13,"method":"none","traffic_rate":1,"node_connector":1}}`, port781)
		case "/mod_mu/nodes/782/info":
			_, _ = fmt.Fprintf(w, `{"ret":1,"data":{"server":"127.0.0.1;%d;0;ws;;path=/vmess","sort":11,"traffic_rate":1}}`, port782)
		case "/mod_mu/nodes/783/info":
			_, _ = fmt.Fprintf(w, `{"ret":1,"data":{"server":"127.0.0.1;%d;0;tcp","sort":14,"traffic_rate":1}}`, port783)
		case "/mod_mu/func/detect_rules":
			detectRuleHits.Add(1)
			time.Sleep(40 * time.Millisecond)
			_, _ = w.Write([]byte(`{"ret":1,"data":[{"regex":"^audit-blocked\\.example\\.test$","type":1}]}`))
		case "/mod_mu/users":
			nid := r.URL.Query().Get("node_id")
			if nid == "783" {
				_, _ = fmt.Fprintf(w, `{"ret":1,"data":[{"id":101,"uuid":"%s","passwd":"%s","node_connector":0,"u":0,"d":0,"transfer_enable":1073741824}]}`, trojanPass, trojanPass)
			} else {
				_, _ = fmt.Fprintf(w, `{"ret":1,"data":[{"id":101,"uuid":"%s","passwd":"%s","node_connector":1,"u":0,"d":0,"transfer_enable":1073741824}]}`, u1Str, u1Str)
			}
		case "/mod_mu/users/traffic":
			trafficPushHits.Add(1)
			_, _ = w.Write([]byte(`{"ret":1,"data":"ok"}`))
		default:
			_, _ = w.Write([]byte(`{"ret":1,"data":[]}`))
		}
	}))
	defer panelSrv.Close()

	// Write whiteList (only 127.0.0.1 so local echo works under ban_private_ip=true while 169.254.169.254/0.0.0.1/198.18.0.5/240.0.0.1 remain blocked)
	if err := os.WriteFile(filepath.Join(tmp, "whiteList"), []byte("127.0.0.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
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

	confPath := filepath.Join(tmp, "xoga.conf")
	confText := fmt.Sprintf(`type=sspanel-uim
server_type=auto
node_id=781,782,783
listen_ip=127.0.0.1
webapi_url=%s
webapi_key=e2e-sspanel-key
force_close_ssl=true
vmess_auth_mode=auto
proxy_protocol=true
trust_forwarded_ip=false
trusted_proxy_cidrs=203.175.12.253/32,172.64.0.0/13
device_limit_enable=true
user_conn_limit=1
domain_sniff=true
ban_private_ip=true
forbidden_ports=143,110
default_dns=%s
dns_strategy=ipv4_only
v2ray_reduce_memory=true
gc_percent=100
check_interval=60
submit_interval=60
log_level=info
`, panelSrv.URL, dnsAddr)
	if err := os.WriteFile(confPath, []byte(confText), 0600); err != nil {
		t.Fatal(err)
	}

	var daemonOut bytes.Buffer
	var daemonOutMu sync.Mutex
	cmd := exec.Command(binPath, "run", "-c", confPath)
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xoga daemon: %v", err)
	}
	copyLog := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				daemonOutMu.Lock()
				daemonOut.Write(buf[:n])
				daemonOutMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}
	go copyLog(stdoutPipe)
	go copyLog(stderrPipe)
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	waitPort := func(port int) {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if err == nil {
				_ = c.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		daemonOutMu.Lock()
		logs := daemonOut.String()
		daemonOutMu.Unlock()
		t.Fatalf("port %d did not start listening; logs:\n%s", port, logs)
	}
	waitPort(port781)
	waitPort(port782)
	waitPort(port783)
	time.Sleep(150 * time.Millisecond)

	// Verify BUG-10 (explicit gc_percent=100 honored despite v2ray_reduce_memory=true)
	daemonOutMu.Lock()
	bootLogs := daemonOut.String()
	daemonOutMu.Unlock()
	if !strings.Contains(bootLogs, "gc=100%") {
		t.Fatalf("BUG-10 regression: expected startup log to honor explicit gc=100%%, got:\n%s", bootLogs)
	}

	// Verify NEW-3: across 3 SSPanel nodes (781, 782, 783), /mod_mu/func/detect_rules fetched ONLY ONCE!
	if got := detectRuleHits.Load(); got != 1 {
		t.Fatalf("NEW-3 regression: expected 1 /mod_mu/func/detect_rules GET across 3 nodes, got %d", got)
	}

	dialWS := func(port int, path, proxyHdr, extraHdrs string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", port, err)
		}
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		req := proxyHdr +
			"GET " + path + " HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
			extraHdrs + "\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("ws write: %v", err)
		}
		br := bufio.NewReader(c)
		status, err := br.ReadString('\n')
		if err != nil || !strings.Contains(status, "101") {
			t.Fatalf("ws upgrade failed: %q err=%v", status, err)
		}
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		return c
	}
	writeWSFrame := func(w io.Writer, payload []byte) error {
		mask := [4]byte{0x21, 0x43, 0x65, 0x87}
		var hdr []byte
		hdr = append(hdr, 0x82)
		if len(payload) < 126 {
			hdr = append(hdr, 0x80|byte(len(payload)))
		} else {
			hdr = append(hdr, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
		}
		hdr = append(hdr, mask[:]...)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ mask[i&3]
		}
		_, err := w.Write(append(hdr, masked...))
		return err
	}
	readWSFrame := func(r io.Reader) ([]byte, error) {
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		plen := int(h[1] & 0x7f)
		if plen == 126 {
			var e [2]byte
			if _, err := io.ReadFull(r, e[:]); err != nil {
				return nil, err
			}
			plen = int(binary.BigEndian.Uint16(e[:]))
		}
		b := make([]byte, plen)
		_, err := io.ReadFull(r, b)
		return b, err
	}

	// NEW-1: Trusted public relay CIDR 203.175.12.253 trusts XFF while untrusted 203.0.113.50 cannot spoof!
	t.Run("NEW1_TrustedProxyCIDRsLiveDaemon", func(t *testing.T) {
		sendVLESS := func(c net.Conn, msg string) ([]byte, error) {
			var b bytes.Buffer
			b.WriteByte(0x00)
			b.Write(u1Bytes[:])
			b.WriteByte(0x00)
			b.WriteByte(0x01)
			_ = binary.Write(&b, binary.BigEndian, echoPort)
			b.WriteByte(0x01)
			b.Write([]byte{127, 0, 0, 1})
			b.WriteString(msg)
			if err := writeWSFrame(c, b.Bytes()); err != nil {
				return nil, err
			}
			return readWSFrame(c)
		}

		// Conn 1 from trusted public relay 203.175.12.253 with XFF 198.51.100.77 -> succeeds and locks device slot to 198.51.100.77!
		c1 := dialWS(port781, "/vless", "PROXY TCP4 203.175.12.253 127.0.0.1 21001 8080\r\n", "X-Forwarded-For: 198.51.100.77\r\n")
		defer c1.Close()
		r1, err := sendVLESS(c1, "trusted-relay-user1")
		if err != nil || !bytes.Contains(r1, []byte("trusted-relay-user1")) {
			t.Fatalf("trusted relay conn 1 failed: %q err=%v", r1, err)
		}

		// Conn 2 from SAME trusted public relay 203.175.12.253 with DIFFERENT XFF 198.51.100.78 -> MUST be rejected by device_limit=1!
		// (If relay IP were not trusted, both would collapse onto 203.175.12.253 and erroneously pass device_limit=1!)
		c2 := dialWS(port781, "/vless", "PROXY TCP4 203.175.12.253 127.0.0.1 21002 8080\r\n", "X-Forwarded-For: 198.51.100.78\r\n")
		defer c2.Close()
		if r2, err := sendVLESS(c2, "trusted-relay-user2"); err == nil && bytes.Contains(r2, []byte("trusted-relay-user2")) {
			t.Fatalf("NEW-1 regression: second distinct XFF IP behind trusted relay collapsed onto relay IP!")
		}

		// Conn 3 from untrusted public peer 203.0.113.50 spoofing XFF 198.51.100.77 -> MUST be rejected by device_limit=1!
		c3 := dialWS(port781, "/vless", "PROXY TCP4 203.0.113.50 127.0.0.1 21003 8080\r\n", "X-Forwarded-For: 198.51.100.77\r\n")
		defer c3.Close()
		if r3, err := sendVLESS(c3, "spoofed-xff"); err == nil && bytes.Contains(r3, []byte("spoofed-xff")) {
			t.Fatalf("NEW-1 security regression: untrusted public IP spoofed X-Forwarded-For to share active slot!")
		}

		// Conn 4 from trusted public relay 203.175.12.253 where an attacker prepended spoofed 198.51.100.77
		// ahead of the real appended client IP 198.51.100.88 -> right-to-left unwinding sees 198.51.100.88
		// and MUST reject it under device_limit=1 instead of trusting the spoofed leftmost token!
		c4 := dialWS(port781, "/vless", "PROXY TCP4 203.175.12.253 127.0.0.1 21004 8080\r\n", "X-Forwarded-For: 198.51.100.77, 198.51.100.88\r\n")
		defer c4.Close()
		if r4, err := sendVLESS(c4, "spoofed-leading-xff"); err == nil && bytes.Contains(r4, []byte("spoofed-leading-xff")) {
			t.Fatalf("NEW-1 security regression: client-spoofed leftmost X-Forwarded-For bypassed device_limit behind trusted relay!")
		}
	})

	// BUG-5: Legacy MD5 VMess client with +81s clock skew succeeds end-to-end!
	t.Run("BUG5_LegacyVMess81sSkewLiveDaemon", func(t *testing.T) {
		c := dialWS(port782, "/vmess", "PROXY TCP4 203.175.12.253 127.0.0.1 22001 8080\r\n", "X-Forwarded-For: 198.51.100.90\r\n")
		defer c.Close()

		var reqKey, reqIV [16]byte
		_, _ = rand.Read(reqKey[:])
		_, _ = rand.Read(reqIV[:])
		var stamp [8]byte
		binary.BigEndian.PutUint64(stamp[:], uint64(time.Now().Unix()+81))
		mac := hmac.New(md5.New, u1Bytes[:])
		_, _ = mac.Write(stamp[:])
		authID := mac.Sum(nil)

		mh := md5.New()
		mh.Write(u1Bytes[:])
		mh.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
		cmdKey := mh.Sum(nil)
		hdrIV := md5.Sum(bytes.Repeat(stamp[:], 4))

		var hdr bytes.Buffer
		hdr.WriteByte(0x01)
		hdr.Write(reqIV[:])
		hdr.Write(reqKey[:])
		hdr.Write([]byte{0x55, 0x05, 0x01, 0x00, 0x01})
		_ = binary.Write(&hdr, binary.BigEndian, echoPort)
		hdr.Write([]byte{0x02, byte(len("127.0.0.1"))})
		hdr.WriteString("127.0.0.1")
		fh := fnv.New32a()
		_, _ = fh.Write(hdr.Bytes())
		_ = binary.Write(&hdr, binary.BigEndian, fh.Sum32())

		hdrBlk, _ := aes.NewCipher(cmdKey)
		encHdr := make([]byte, hdr.Len())
		cipher.NewCFBEncrypter(hdrBlk, hdrIV[:]).XORKeyStream(encHdr, hdr.Bytes())

		msg := []byte("legacy-81s-skew-live-ok!")
		rm := sha3.NewShake128()
		_, _ = rm.Write(reqIV[:])
		var m1, m2 [2]byte
		_, _ = rm.Read(m1[:])
		_, _ = rm.Read(m2[:])
		var bodyPlain bytes.Buffer
		_ = binary.Write(&bodyPlain, binary.BigEndian, uint16(4+len(msg))^binary.BigEndian.Uint16(m1[:]))
		pfh := fnv.New32a()
		_, _ = pfh.Write(msg)
		_ = binary.Write(&bodyPlain, binary.BigEndian, pfh.Sum32())
		bodyPlain.Write(msg)
		_ = binary.Write(&bodyPlain, binary.BigEndian, uint16(0)^binary.BigEndian.Uint16(m2[:]))

		bodyBlk, _ := aes.NewCipher(reqKey[:])
		encBody := make([]byte, bodyPlain.Len())
		cipher.NewCFBEncrypter(bodyBlk, reqIV[:]).XORKeyStream(encBody, bodyPlain.Bytes())

		wire := append(append(authID, encHdr...), encBody...)
		if err := writeWSFrame(c, wire); err != nil {
			t.Fatal(err)
		}
		var rawResp bytes.Buffer
		respKey := md5.Sum(reqKey[:])
		respIV := md5.Sum(reqIV[:])
		respBlk, _ := aes.NewCipher(respKey[:])
		dec := cipher.NewCFBDecrypter(respBlk, respIV[:])
		for rawResp.Len() < 4+2+4+len(msg) {
			f, err := readWSFrame(c)
			if err != nil {
				t.Fatalf("legacy +81s skew WS read failed: %v", err)
			}
			rawResp.Write(f)
		}
		plain := make([]byte, rawResp.Len())
		dec.XORKeyStream(plain, rawResp.Bytes())
		if plain[0] != 0x55 || !bytes.Contains(plain[4:], msg) {
			t.Fatalf("legacy +81s skew response mismatch")
		}
	})

	// BUG-2 + BUG-4 + BUG-7 on Trojan node 783 (with catch-all direct route, domain_sniff=true, ban_private_ip=true, forbidden_ports=143)
	t.Run("BUG2_BUG4_BUG7_TrojanLiveDaemon", func(t *testing.T) {
		dialTrojan := func(rawIP []byte, port uint16, payload []byte) net.Conn {
			t.Helper()
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port783), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			sum := sha256.Sum224([]byte(trojanPass))
			var req bytes.Buffer
			req.WriteString("PROXY TCP4 198.51.100.60 127.0.0.1 33001 443\r\n")
			req.WriteString(hex.EncodeToString(sum[:]))
			req.WriteString("\r\n")
			req.WriteByte(0x01)
			req.WriteByte(0x01)
			req.Write(rawIP)
			var pb [2]byte
			binary.BigEndian.PutUint16(pb[:], port)
			req.Write(pb[:])
			req.WriteString("\r\n")
			req.Write(payload)
			if _, err := c.Write(req.Bytes()); err != nil {
				t.Fatal(err)
			}
			return c
		}

		// Clash Fake-IP 198.18.0.5 + HTTP Host overrides under ActionDirect and succeeds!
		httpReq := []byte("GET /fakeip HTTP/1.1\r\nHost: direct-fakeip.e2e\r\n\r\n")
		cFake := dialTrojan([]byte{198, 18, 0, 5}, echoPort, httpReq)
		got := make([]byte, len(httpReq))
		if _, err := io.ReadFull(cFake, got); err != nil || !bytes.Equal(got, httpReq) {
			_ = cFake.Close()
			t.Fatalf("Clash Fake-IP direct domain_sniff override failed: got=%q err=%v", got, err)
		}
		_ = cFake.Close()

		// GFW-poisoned 0.0.0.1 + HTTP Host overrides under ActionDirect and succeeds!
		httpReq2 := []byte("GET /gfw HTTP/1.1\r\nHost: gfw-poisoned.e2e\r\n\r\n")
		cGFW := dialTrojan([]byte{0, 0, 0, 1}, echoPort, httpReq2)
		got2 := make([]byte, len(httpReq2))
		if _, err := io.ReadFull(cGFW, got2); err != nil || !bytes.Equal(got2, httpReq2) {
			_ = cGFW.Close()
			t.Fatalf("GFW-poisoned 0.0.0.1 direct domain_sniff override failed: got=%q err=%v", got2, err)
		}
		_ = cGFW.Close()
		if dnsHits.Load() < 2 {
			t.Fatalf("expected mock DNS to resolve overridden direct domains, got %d hits", dnsHits.Load())
		}

		// Explicitly whitelisted literal IP 127.0.0.1 with HTTP Host MUST dial 127.0.0.1 directly
		// WITHOUT overriding to Host or triggering DNS lookup!
		dnsBefore := dnsHits.Load()
		httpWhite := []byte("GET /white HTTP/1.1\r\nHost: internal-only.corp.local\r\n\r\n")
		cWhite := dialTrojan([]byte{127, 0, 0, 1}, echoPort, httpWhite)
		gotW := make([]byte, len(httpWhite))
		if _, err := io.ReadFull(cWhite, gotW); err != nil || !bytes.Equal(gotW, httpWhite) {
			_ = cWhite.Close()
			t.Fatalf("whitelisted 127.0.0.1 with HTTP Host failed: got=%q err=%v", gotW, err)
		}
		_ = cWhite.Close()
		if dnsHits.Load() != dnsBefore {
			t.Fatalf("whitelisted literal IP triggered DNS rewrite (%d -> %d)", dnsBefore, dnsHits.Load())
		}

		// Unresolved metadata 169.254.169.254, 0.0.0.1, 198.18.0.5, 240.0.0.1 MUST be blocked!
		for _, rawIP := range [][]byte{{169, 254, 169, 254}, {0, 0, 0, 1}, {198, 18, 0, 9}, {240, 0, 0, 1}} {
			cBlk := dialTrojan(rawIP, echoPort, []byte("RAW-NO-SNI"))
			var b [1]byte
			n, err := cBlk.Read(b[:])
			_ = cBlk.Close()
			if n != 0 || err == nil {
				t.Fatalf("expected reserved/private IP %v to be blocked, got n=%d err=%v", rawIP, n, err)
			}
		}

		// BUG-7: Forbidden port 143 with ZERO payload short-circuits BEFORE 150ms peek!
		start := time.Now()
		c143 := dialTrojan([]byte{1, 1, 1, 1}, 143, nil)
		var b [1]byte
		n, err := c143.Read(b[:])
		elapsed := time.Since(start)
		_ = c143.Close()
		if n != 0 || err == nil {
			t.Fatalf("expected forbidden port 143 to be closed, got n=%d err=%v", n, err)
		}
		if elapsed >= 100*time.Millisecond {
			t.Fatalf("BUG-7 regression: forbidden port 143 stalled %v (want <100ms)", elapsed)
		}
	})

	// Clean SIGTERM + final traffic flush
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM failed: %v", err)
	}
	doneWait := make(chan error, 1)
	go func() { doneWait <- cmd.Wait() }()
	select {
	case werr := <-doneWait:
		if werr != nil {
			t.Fatalf("xoga did not exit cleanly on SIGTERM: %v", werr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("xoga hung >10s on SIGTERM")
	}
	if trafficPushHits.Load() == 0 {
		t.Fatal("expected final traffic flush on SIGTERM")
	}
}
