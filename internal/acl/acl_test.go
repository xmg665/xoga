package acl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSogaRoutesTOMLAndGeositeUnlock(t *testing.T) {
	tomlPath := filepath.Join(t.TempDir(), "routes.toml")
	content := `
[[routes]]
enable = true
name = "ai-streaming-unlock"
balance = "round_robin"
rules = [
  "geosite:openai",
  "geosite:disney",
  "bahamut.com.tw"
]

[[routes.outs]]
type = "socks5"
server = "127.0.0.1"
port = 40000

[[routes.outs]]
type = "ss"
server = "10.0.0.2"
port = 8388
cipher = "aes-256-gcm"
password = "secret"

[[outbound]]
tag = "v6-direct"
protocol = "freedom"
listen_strategy = "ipv6_only"

[[rule]]
type = "field"
domain = ["geosite:netflix"]
outboundTag = "v6-direct"
`
	if err := os.WriteFile(tomlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(true, "", "", tomlPath, nil)

	// 1. Round-robin across the 2 outs for geosite:openai (`chatgpt.com`)
	d1 := eng.Decide("chatgpt.com", "", "tls")
	if d1.Action != ActionProxy || len(d1.Outbounds) != 2 || d1.Outbounds[0].Type != "socks5" {
		t.Fatalf("unexpected first round-robin decision: %+v", d1)
	}
	d2 := eng.Decide("disneyplus.com", "", "tls")
	if d2.Action != ActionProxy || len(d2.Outbounds) != 2 || d2.Outbounds[0].Type != "ss" {
		t.Fatalf("unexpected second round-robin decision: %+v", d2)
	}

	// 2. Xray-style [[outbound]] + [[rule]] with listen_strategy = ipv6_only for geosite:netflix
	nf := eng.Decide("nflxvideo.net", "", "tls")
	if nf.Action != ActionProxy || len(nf.Outbounds) != 1 || nf.Outbounds[0].ListenStrategy != "ipv6_only" {
		t.Fatalf("unexpected ipv6_only direct route: %+v", nf)
	}
}

func TestDesktopSogaWARPRoutesAndForbiddenPorts(t *testing.T) {
	tomlPath := filepath.Join(t.TempDir(), "routes.toml")
	// Exact format from user's production soga routes.toml (`enable=true`, `[[routes.Outs]]`, `type="socks"`, catch-all `*`)
	content := `enable=true

# ---------- AI 走 WARP ----------
[[routes]]
rules=[
	"domain:openai.com",
	"domain:chatgpt.com",
	"domain:claude.ai",
	"domain:gemini.google.com",
	"domain:perplexity.ai",
	"domain:x.ai",
	"domain:grok.com"
]

[[routes.Outs]]
type="socks"
server="127.0.0.1"
port=40000

# ---------- 兜底直连，必须放最后 ----------
[[routes]]
rules=["*"]
[[routes.Outs]]
type="direct"
`
	if err := os.WriteFile(tomlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(true, "", "", tomlPath, nil)
	eng.SetPortAndPrivatePolicy("25,26,6881-6999,1024-1299,5354", false)

	// AI domain -> socks5 127.0.0.1:40000
	ai := eng.DecideWithPort("chatgpt.com", 443, "", "tls")
	if ai.Action != ActionProxy || len(ai.Outbounds) != 1 || ai.Outbounds[0].Type != "socks5" || ai.Outbounds[0].Port != 40000 {
		t.Fatalf("expected WARP socks5:40000 for chatgpt.com, got %+v", ai)
	}
	if !eng.HasRouteForDomain("api.openai.com") {
		t.Fatal("expected HasRouteForDomain(api.openai.com) == true")
	}

	// Non-AI domain -> hits catch-all `*` direct, and HasRouteForDomain must be FALSE!
	normal := eng.DecideWithPort("www.apple.com", 443, "", "tls")
	if normal.Action != ActionDirect {
		t.Fatalf("expected ActionDirect for www.apple.com, got %+v", normal)
	}
	if eng.HasRouteForDomain("www.apple.com") {
		t.Fatal("catch-all direct rule must not mark www.apple.com as proxy-routed")
	}

	// Forbidden port 25 and BT range 6889 -> ActionBlock
	if eng.DecideWithPort("smtp.gmail.com", 25, "", "").Action != ActionBlock {
		t.Fatal("expected port 25 to be blocked")
	}
	if eng.DecideWithPort("tracker.example.com", 6889, "", "").Action != ActionBlock {
		t.Fatal("expected port 6889 in range 6881-6999 to be blocked")
	}
}
