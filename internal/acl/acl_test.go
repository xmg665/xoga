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

func TestMultiNodeExitListenBindingRoutesTOML(t *testing.T) {
	tomlPath := filepath.Join(t.TempDir(), "routes.toml")
	content := `
[[routes]]
rules=["node_id:781"]
[[routes.Outs]]
listen = "10.163.0.100"
type = "direct"

[[routes]]
rules=["node_id:782"]
[[routes.Outs]]
listen = "10.163.0.108"
type = "direct"

[[routes]]
rules=["node_id:851", "geosite:openai"]
[[routes.Outs]]
type = "socks"
server = "127.0.0.1"
port = 40000
`
	if err := os.WriteFile(tomlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(true, "", "", tomlPath, nil)

	r781 := eng.DecideForNode(781, "www.youtube.com", 443, "", "tls")
	if r781.Action != ActionProxy || len(r781.Outbounds) != 1 || r781.Outbounds[0].Type != "direct" || r781.Outbounds[0].ListenIPv4 != "10.163.0.100" {
		t.Fatalf("expected node 781 source bind 10.163.0.100, got %+v", r781)
	}

	r782 := eng.DecideForNode(782, "1.1.1.1", 443, "", "tls")
	if r782.Action != ActionProxy || len(r782.Outbounds) != 1 || r782.Outbounds[0].ListenIPv4 != "10.163.0.108" {
		t.Fatalf("expected node 782 source bind 10.163.0.108, got %+v", r782)
	}

	// Scoped node_id + domain rule: node 851 + chatgpt.com -> socks5:40000, node 851 + apple.com -> ActionDirect
	r851AI := eng.DecideForNode(851, "chatgpt.com", 443, "", "tls")
	if r851AI.Action != ActionProxy || r851AI.Outbounds[0].Type != "socks5" {
		t.Fatalf("expected node 851 chatgpt.com -> WARP socks5, got %+v", r851AI)
	}
	r851Direct := eng.DecideForNode(851, "www.apple.com", 443, "", "tls")
	if r851Direct.Action != ActionDirect {
		t.Fatalf("expected node 851 www.apple.com -> ActionDirect, got %+v", r851Direct)
	}
	if r781.IsRemoteProxy {
		t.Fatal("direct source-IP exit binding must NOT set IsRemoteProxy=true")
	}

	// Verify quoted comma-containing rules (`node_id:781,782` & `{1,3}` regex) + SIP002 base64 ss:// + panel direct route
	toml2 := filepath.Join(t.TempDir(), "routes2.toml")
	_ = os.WriteFile(toml2, []byte(`
[[routes]]
rules = ["node_id:781,782", "regexp:^Video[0-9]{1,3}\\.example\\.com$"]
outbound = "ss://YWVzLTEyOC1nY206bXlzZWNyZXQ=@10.0.0.9:8388"
`), 0644)
	eng2 := NewEngine(true, "", "", toml2, []DynamicRoute{
		{Matches: []string{"domain:direct-panel.com"}, Action: "direct", ActionValue: ""},
	})
	d782 := eng2.DecideForNode(782, "video42.example.com", 443, "", "tls")
	if d782.Action != ActionProxy || d782.Outbounds[0].Cipher != "aes-128-gcm" || d782.Outbounds[0].Password != "mysecret" {
		t.Fatalf("quoted comma / case-insensitive regex / SIP002 ss:// failed: %+v", d782)
	}
	dp := eng2.DecideForNode(782, "sub.direct-panel.com", 443, "", "tls")
	if dp.Action != ActionDirect || !dp.MatchedRule {
		t.Fatalf("panel direct route with empty ActionValue was dropped: %+v", dp)
	}
}

func BenchmarkACLSuffixMap10000Domains(b *testing.B) {
	cr := newCompiledRule("bench", ActionBlock)
	for i := 0; i < 10000; i++ {
		cr.addPattern("domain:blocked-site-" + string(rune('a'+(i%26))) + ".example" + string(rune('0'+(i%10))) + ".org")
	}
	cr.addPattern("domain:openai.com")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !cr.matchDomain("api.chat.openai.com") {
			b.Fatal("expected match")
		}
		if cr.matchDomain("cdn.cloudflare.net") {
			b.Fatal("unexpected match")
		}
	}
}
