package sniff

import "testing"

func TestSniffHTTPHostAndBT(t *testing.T) {
	httpReq := []byte("GET /index.html HTTP/1.1\r\nUser-Agent: curl\r\nHost: api.example.com:8080\r\n\r\n")
	res := Inspect(httpReq)
	if res.Protocol != "http" || res.Domain != "api.example.com" {
		t.Fatalf("unexpected HTTP sniff result: %+v", res)
	}

	btPayload := append([]byte("\x13BitTorrent protocol"), make([]byte, 28)...)
	btRes := Inspect(btPayload)
	if btRes.Protocol != "bittorrent" {
		t.Fatalf("expected bittorrent detection, got %+v", btRes)
	}
}

func TestSniffTLSClientHello(t *testing.T) {
	// Minimal synthetic TLS 1.2 ClientHello carrying SNI "video.netflix.com"
	sni := "video.netflix.com"
	ext := []byte{
		0x00, 0x00, // ext type: server_name
		0x00, byte(5 + len(sni)),
		0x00, byte(3 + len(sni)),
		0x00, // host_name
		0x00, byte(len(sni)),
	}
	ext = append(ext, []byte(sni)...)

	body := make([]byte, 0, 64+len(ext))
	body = append(body, 0x03, 0x03)             // client version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id len 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // 1 cipher suite
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, 0x00, byte(len(ext)))   // extensions len
	body = append(body, ext...)

	handshake := append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	record := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(handshake))}, handshake...)

	res := Inspect(record)
	if res.Protocol != "tls" || res.Domain != sni {
		t.Fatalf("expected TLS SNI %q, got %+v", sni, res)
	}
}

func BenchmarkSniffTLSClientHello(b *testing.B) {
	sni := "edge.cloudflare.com"
	ext := append([]byte{0x00, 0x00, 0x00, byte(5 + len(sni)), 0x00, byte(3 + len(sni)), 0x00, 0x00, byte(len(sni))}, sni...)
	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(hs))}, hs...)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := SniffTLSClientHello(rec)
		if !ok {
			b.Fatal("sniff failed")
		}
	}
}
