package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildMockDNSResponse builds a minimal RFC 1035 response for a single question packet.
func buildMockDNSResponse(req []byte, ipv4 [4]byte, ipv6 [16]byte) []byte {
	if len(req) < 12 {
		return nil
	}
	qtype := binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2])
	resp := make([]byte, 0, len(req)+32)
	resp = append(resp, req[0], req[1]) // Transaction ID
	resp = append(resp, 0x81, 0x80)     // QR=1, RD=1, RA=1, RCODE=0
	resp = append(resp, 0x00, 0x01)     // QDCOUNT=1

	hasAns := (qtype == qTypeA && ipv4 != [4]byte{}) || (qtype == qTypeAAAA && ipv6 != [16]byte{})
	if hasAns {
		resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	} else {
		resp = append(resp, 0x00, 0x00)
	}
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)
	resp = append(resp, req[12:]...) // echo Question section

	if hasAns {
		resp = append(resp, 0xC0, 0x0C) // pointer to question name at offset 12
		var tail [10]byte
		binary.BigEndian.PutUint16(tail[0:2], qtype)
		binary.BigEndian.PutUint16(tail[2:4], 1)   // IN
		binary.BigEndian.PutUint32(tail[4:8], 120) // TTL=120s
		if qtype == qTypeA {
			binary.BigEndian.PutUint16(tail[8:10], 4)
			resp = append(resp, tail[:]...)
			resp = append(resp, ipv4[:]...)
		} else {
			binary.BigEndian.PutUint16(tail[8:10], 16)
			resp = append(resp, tail[:]...)
			resp = append(resp, ipv6[:]...)
		}
	}
	return resp
}

func startMockUDPDNS(t *testing.T, v4 [4]byte) (string, func()) {
	t.Helper()
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
			ans := buildMockDNSResponse(buf[:n], v4, [16]byte{})
			if ans != nil {
				_, _ = pc.WriteTo(ans, addr)
			}
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

func TestDNSUnlockUDPDoHAndHotReload(t *testing.T) {
	udpAddr1, stopUDP1 := startMockUDPDNS(t, [4]byte{198, 51, 100, 77})
	defer stopUDP1()

	udpAddr2, stopUDP2 := startMockUDPDNS(t, [4]byte{203, 0, 113, 88})
	defer stopUDP2()

	v6Unlock := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}
	dohSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ans := buildMockDNSResponse(body, [4]byte{192, 0, 2, 55}, v6Unlock)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(ans)
	}))
	defer dohSrv.Close()

	dnsFile := filepath.Join(t.TempDir(), "dns.yml")
	yml1 := `
"` + udpAddr1 + `":
  strategy: ipv4_only
  rules:
    - geosite:netflix
    - domain:hulu.com

"` + dohSrv.URL + `/dns-query":
  strategy: ipv6_only
  rules:
    - geosite:openai
`
	if err := os.WriteFile(dnsFile, []byte(yml1), 0644); err != nil {
		t.Fatal(err)
	}

	res := NewResolver(dnsFile, "", nil, "ipv4_first")
	ctx := context.Background()

	// 1. Netflix domain -> UDP unlock DNS -> 198.51.100.77
	ipNf, err := res.Resolve(ctx, "www.netflix.com", 0, false)
	if err != nil || ipNf.String() != "198.51.100.77" {
		t.Fatalf("expected 198.51.100.77 for www.netflix.com, got %v (err=%v)", ipNf, err)
	}

	// 2. OpenAI domain -> DoH unlock server with ipv6_only -> 2001:db8::42
	ipOAI, err := res.Resolve(ctx, "chatgpt.com", 0, false)
	if err != nil || ipOAI.String() != "2001:db8::42" {
		t.Fatalf("expected 2001:db8::42 for chatgpt.com via DoH ipv6_only, got %v (err=%v)", ipOAI, err)
	}

	// 3. Hot reload dns.yml to point geosite:netflix to udpAddr2 (203.0.113.88)
	yml2 := `
"` + udpAddr2 + `":
  strategy: ipv4_only
  rules:
    - geosite:netflix
`
	future := time.Now().Add(10 * time.Second)
	if err := os.WriteFile(dnsFile, []byte(yml2), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(dnsFile, future, future)
	res.lastCheck.Store(0) // force mtime check window immediately

	ipNf2, err := res.Resolve(ctx, "fast.com", 0, false) // fast.com is in geosite:netflix!
	if err != nil || ipNf2.String() != "203.0.113.88" {
		t.Fatalf("expected hot-reloaded IP 203.0.113.88 for fast.com, got %v (err=%v)", ipNf2, err)
	}
}

func TestSingleflightCoalescingAndServeStale(t *testing.T) {
	var upstreamQueries atomic.Int32
	var dropPackets atomic.Bool

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			upstreamQueries.Add(1)
			if dropPackets.Load() {
				continue
			}
			time.Sleep(25 * time.Millisecond)
			ans := buildMockDNSResponse(buf[:n], [4]byte{198, 18, 0, 99}, [16]byte{})
			if ans != nil {
				_, _ = pc.WriteTo(ans, addr)
			}
		}
	}()

	res := NewResolver("", "", []string{pc.LocalAddr().String()}, "ipv4_only")

	// Launch 32 concurrent lookups for the exact same uncached domain
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, rerr := res.Resolve(context.Background(), "coalesce.openai.com", 0, false)
			if rerr != nil || ip.String() != "198.18.0.99" {
				t.Errorf("unexpected resolve result: ip=%v err=%v", ip, rerr)
			}
		}()
	}
	wg.Wait()

	if got := upstreamQueries.Load(); got != 1 {
		t.Fatalf("expected singleflight to coalesce 32 concurrent DNS queries into 1, got %d", got)
	}

	// Expire cache entry artificially and simulate upstream outage -> verify RFC 8767 serve-stale fallback!
	res.cacheMu.Lock()
	for k, v := range res.cache {
		v.expires = time.Now().Unix() - 10
		res.cache[k] = v
	}
	res.cacheMu.Unlock()
	dropPackets.Store(true)

	shortCtx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	staleIP, err := res.Resolve(shortCtx, "coalesce.openai.com", 0, false)
	if err != nil || staleIP.String() != "198.18.0.99" {
		t.Fatalf("expected RFC 8767 serve-stale IP 198.18.0.99 during upstream timeout, got %v (err=%v)", staleIP, err)
	}
}
