package acl

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBUG4IsReservedOrPrivateIPCoversZeroBenchmarkAndClassE(t *testing.T) {
	mustBlock := []string{
		"0.0.0.0",
		"0.0.0.1",
		"0.1.0.1",
		"0.0.1.50",
		"0.255.255.255",
		"10.0.0.1",
		"100.64.0.1",
		"100.100.100.200",
		"127.0.0.1",
		"169.254.169.254",
		"172.16.0.1",
		"192.168.1.1",
		"198.18.0.1",
		"198.18.0.5",
		"198.19.255.254",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"fe80::1",
		"fc00::1",
		"fd12:3456::1",
		"::ffff:0.0.0.1",
		"::ffff:198.18.0.5",
		"::ffff:240.0.0.1",
		"::ffff:169.254.169.254",
	}
	for _, s := range mustBlock {
		ip := netip.MustParseAddr(s)
		if !IsReservedOrPrivateIP(ip) {
			t.Fatalf("expected IsReservedOrPrivateIP(%s) == true", s)
		}
	}

	mustAllow := []string{
		"1.1.1.1",
		"8.8.8.8",
		"100.63.255.255",
		"100.128.0.1",
		"198.17.255.255",
		"198.20.0.1",
		"223.255.255.255",
		"2606:4700::1111",
		"2001:4860:4860::8888",
	}
	for _, s := range mustAllow {
		ip := netip.MustParseAddr(s)
		if IsReservedOrPrivateIP(ip) {
			t.Fatalf("expected IsReservedOrPrivateIP(%s) == false", s)
		}
	}
}

func TestBUG8ReloadNowRetainsRoutesOnTruncationOrMalformedTOMLAndRecovers(t *testing.T) {
	tmp := t.TempDir()
	rtPath := filepath.Join(tmp, "routes.toml")

	validTOML1 := `
[[routes]]
name = "ai-warp"
rules = ["domain:chatgpt.com", "domain:openai.com"]
[[routes.outs]]
type = "socks5"
server = "127.0.0.1"
port = 40000
`
	if err := os.WriteFile(rtPath, []byte(validTOML1), 0644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(true, "", "", rtPath, nil)
	if r := eng.DecideWithPort("chatgpt.com", 443, "", "tls"); r.Action != ActionProxy || r.RuleName != "ai-warp" {
		t.Fatalf("initial routes.toml load failed: %+v", r)
	}

	// 1. Simulate non-atomic truncation to 0 bytes (e.g., shell `> routes.toml`)
	if err := os.WriteFile(rtPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	future1 := time.Now().Add(5 * time.Second)
	_ = os.Chtimes(rtPath, future1, future1)
	eng.reloadNow(false)

	if r := eng.DecideWithPort("chatgpt.com", 443, "", "tls"); r.Action != ActionProxy || r.RuleName != "ai-warp" {
		t.Fatalf("0-byte truncated routes.toml wiped previous valid routes: %+v", r)
	}

	// 2. Simulate half-written / unclosed multiline array TOML
	halfWritten := `
[[routes]]
name = "ai-warp-v2"
rules = [
  "domain:claude.ai",
`
	if err := os.WriteFile(rtPath, []byte(halfWritten), 0644); err != nil {
		t.Fatal(err)
	}
	future2 := time.Now().Add(10 * time.Second)
	_ = os.Chtimes(rtPath, future2, future2)
	eng.reloadNow(false)

	if r := eng.DecideWithPort("chatgpt.com", 443, "", "tls"); r.Action != ActionProxy || r.RuleName != "ai-warp" {
		t.Fatalf("half-written malformed routes.toml wiped previous valid routes: %+v", r)
	}

	// 3. Complete writing valid updated TOML (even at SAME mtime as future2!) -> must reload cleanly!
	validTOML2 := `
[[routes]]
name = "ai-warp-v2"
rules = [
  "domain:claude.ai"
]
[[routes.outs]]
type = "socks5"
server = "127.0.0.1"
port = 40001
`
	if err := os.WriteFile(rtPath, []byte(validTOML2), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(rtPath, future2, future2) // identical mtime to the rejected write, proving routeStat wasn't latched!
	eng.reloadNow(false)

	if r := eng.DecideWithPort("claude.ai", 443, "", "tls"); r.Action != ActionProxy || r.RuleName != "ai-warp-v2" || r.Outbounds[0].Port != 40001 {
		t.Fatalf("routes.toml failed to recover after valid write at same mtime: %+v", r)
	}

	// 4. Explicit `enable = false` intentionally disables file routes cleanly.
	if err := os.WriteFile(rtPath, []byte("enable = false\n"), 0644); err != nil {
		t.Fatal(err)
	}
	future3 := time.Now().Add(20 * time.Second)
	_ = os.Chtimes(rtPath, future3, future3)
	eng.reloadNow(false)

	if r := eng.DecideWithPort("claude.ai", 443, "", "tls"); r.Action != ActionDirect {
		t.Fatalf("explicit enable=false did not disable file routes: %+v", r)
	}
}
