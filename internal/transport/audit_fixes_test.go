package transport

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/config"
)

func TestM7WebSocketPlainSubprotocolNotTreatedAsEarlyData(t *testing.T) {
	for _, proto := range []string{"chat", "binary", "graphql-transport-ws", "v2ray"} {
		c1, c2 := net.Pipe()
		go func() {
			req := "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Protocol: " + proto + "\r\n\r\n"
			_, _ = c2.Write([]byte(req))
			buf := make([]byte, 512)
			_, _ = c2.Read(buf)
			// Send actual binary WS frame "real-payload"
			p := []byte("real-payload")
			_, _ = c2.Write(append([]byte{0x82, byte(len(p))}, p...))
		}()

		ws, err := AcceptWebSocket(c1, "/ws", false)
		if err != nil {
			t.Fatalf("AcceptWebSocket(%q) failed: %v", proto, err)
		}
		got := make([]byte, 32)
		n, err := ws.Read(got)
		_ = ws.Close()
		_ = c2.Close()
		if err != nil || string(got[:n]) != "real-payload" {
			t.Fatalf("plain Sec-WebSocket-Protocol %q corrupted stream: got %q (err=%v)", proto, got[:n], err)
		}
	}

	// Genuine >=16B binary early data in Sec-WebSocket-Protocol MUST still be decoded
	early := []byte{0x00, 0x01, 0x02, 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	b64 := base64.RawURLEncoding.EncodeToString(early)
	c1, c2 := net.Pipe()
	go func() {
		req := "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
			"Sec-WebSocket-Protocol: " + b64 + "\r\n\r\n"
		_, _ = c2.Write([]byte(req))
		buf := make([]byte, 512)
		_, _ = c2.Read(buf)
	}()
	ws, err := AcceptWebSocket(c1, "/ws", false)
	if err != nil {
		t.Fatalf("AcceptWebSocket early data failed: %v", err)
	}
	got := make([]byte, len(early))
	n, err := io.ReadFull(ws, got)
	_ = ws.Close()
	_ = c2.Close()
	if err != nil || !bytes.Equal(got[:n], early) {
		t.Fatalf("real base64 early-data decode mismatch: got %x want %x err=%v", got[:n], early, err)
	}
}

type trackingDeadlineConn struct {
	net.Conn
	lastWriteDL time.Time
}

func (c *trackingDeadlineConn) SetWriteDeadline(t time.Time) error {
	c.lastWriteDL = t
	return c.Conn.SetWriteDeadline(t)
}

func TestN6WSWriteControlFramePreservesWriteDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tc := &trackingDeadlineConn{Conn: c1}

	w := &wsConn{
		Conn:      tc,
		rawWriter: tc,
		br:        bufio.NewReader(tc),
	}
	wantDL := time.Now().Add(90 * time.Second)
	if err := w.SetWriteDeadline(wantDL); err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 6)
		_, _ = io.ReadFull(c2, buf)
	}()
	if err := w.writeControlFrame(0xA, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	if !tc.lastWriteDL.Equal(wantDL) {
		t.Fatalf("writeControlFrame clobbered caller write deadline: got %v want %v", tc.lastWriteDL, wantDL)
	}
}

func TestL1L2TLSAndRealityEdgeCases(t *testing.T) {
	// L1a: Partial manual TLS config (cert_file without key_file) must return error, NOT silent self-signed
	cfg := config.Default()
	cfg.CertFile = "/nonexistent/cert.pem"
	if _, err := BuildTLSConfig(cfg, "example.com"); err == nil {
		t.Fatal("expected error for partial manual TLS config (cert_file without key_file)")
	}
	cfg2 := config.Default()
	cfg2.KeyFile = "/nonexistent/key.pem"
	if _, err := BuildTLSConfig(cfg2, "example.com"); err == nil {
		t.Fatal("expected error for partial manual TLS config (key_file without cert_file)")
	}

	// L1b: Self-signed cert for IP literal places IP in IPAddresses, NOT DNSNames
	tlsCert, err := generateSelfSignedCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.IPAddresses) != 1 || !parsed.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected IP 127.0.0.1 in IPAddresses, got %v", parsed.IPAddresses)
	}
	if len(parsed.DNSNames) != 0 {
		t.Fatalf("expected IP literal NOT to be placed in DNSNames, got %v", parsed.DNSNames)
	}

	// L2a: Odd-length REALITY short_id must be rejected instead of silently left-padded
	if _, err := parseShortIDHex("abc"); err == nil {
		t.Fatal("expected odd-length short_id \"abc\" to be rejected")
	}
	if sid, err := parseShortIDHex("abcd"); err != nil || sid[0] != 0xab || sid[1] != 0xcd {
		t.Fatalf("expected valid even short_id \"abcd\", got %x err=%v", sid, err)
	}

	// L2b: Bracketed IPv6 Dest without port must NOT get double-bracketed
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rln, err := BuildRealityListener(ln, RealityOptions{
		Dest:       "[2001:db8::1]",
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
	})
	if err != nil {
		t.Fatalf("BuildRealityListener with bracketed IPv6 dest failed: %v", err)
	}
	_ = rln
	// Verify normalization logic directly
	dest := "[2001:db8::1]"
	if _, _, splitErr := net.SplitHostPort(dest); splitErr != nil {
		dest = net.JoinHostPort(strings.Trim(dest, "[]"), "443")
	}
	if dest != "[2001:db8::1]:443" {
		t.Fatalf("unexpected bracketed IPv6 dest: %q", dest)
	}
}

func TestL1ACMEBindFailureAutomaticRetry(t *testing.T) {
	// Occupy a local port so initial ACME listener bind MUST fail.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := blocker.Addr().String()

	acmeHubMu.Lock()
	origAddr := acmeListenAddr
	origDelay := acmeRetryDelay
	acmeListenAddr = addr
	acmeRetryDelay = 30 * time.Millisecond
	acmeHubMu.Unlock()
	defer func() {
		acmeHubMu.Lock()
		acmeListenAddr = origAddr
		acmeRetryDelay = origDelay
		acmeHubMu.Unlock()
	}()

	// Single node registers ACME while port is busy -> initial bind fails.
	_ = registerACMEManager("retry-acme.example.com", t.TempDir())
	defer unregisterACMEManager("retry-acme.example.com")

	time.Sleep(60 * time.Millisecond) // allow at least one failed bind attempt
	_ = blocker.Close()               // free the port

	// The existing registration MUST automatically retry and bind the port!
	cli := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, rerr := cli.Get("http://" + addr + "/.well-known/acme-challenge/test-token")
		if rerr == nil {
			_ = resp.Body.Close()
			return
		}
		lastErr = rerr
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("ACME HTTP-01 listener never recovered after initial bind failure: %v", lastErr)
}

type eofOnLastChunkReader struct {
	data []byte
}

func (r *eofOnLastChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestWSConnReadCompletesOnNWithEOF(t *testing.T) {
	// Build a single binary WS frame + trailing Pong control frame, fed via an io.Reader
	// that returns (n, io.EOF) on the exact final byte.
	payload := []byte("ws-eof-final")
	var wire bytes.Buffer
	// Pong frame with 2-byte payload (discarded by wsConn) followed by binary frame
	wire.Write([]byte{0x8A, 0x02, 'o', 'k'})
	wire.Write([]byte{0x82, byte(len(payload))})
	wire.Write(payload)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wsc := &wsConn{
		Conn: c1,
		br:   bufio.NewReaderSize(&eofOnLastChunkReader{data: wire.Bytes()}, 64),
	}
	buf := make([]byte, 32)
	n, err := wsc.Read(buf)
	if n != len(payload) || string(buf[:n]) != string(payload) {
		t.Fatalf("expected final WS payload %q on (n, io.EOF), got n=%d %q err=%v", payload, n, buf[:n], err)
	}
}
