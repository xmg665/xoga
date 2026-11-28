package acl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestH8UnknownGeositeWhitelistPrivateIPAndUnresolvedRoute(t *testing.T) {
	// 1. Unknown geosite:* must NOT fall back to keyword:<tag>
	if list, ok := ExpandGeosite("geosite:cn"); ok || len(list) > 0 {
		t.Fatalf("unknown geosite:cn must not expand to keyword:cn, got %v (ok=%v)", list, ok)
	}
	if list, ok := ExpandGeosite("geosite:us"); ok || len(list) > 0 {
		t.Fatalf("unknown geosite:us must not expand to keyword:us, got %v (ok=%v)", list, ok)
	}

	tmp := t.TempDir()
	wlPath := filepath.Join(tmp, "whiteList")
	blPath := filepath.Join(tmp, "blockList")
	rtPath := filepath.Join(tmp, "routes.toml")

	if err := os.WriteFile(wlPath, []byte("10.1.2.3\n192.168.50.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blPath, []byte("geosite:cn\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rtPath, []byte(`
[[routes]]
name = "broken-typo-route"
rules = ["domain:example.org"]
outbound = "nonexistent_tag"
`), 0644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(true, wlPath, blPath, rtPath, nil)
	eng.SetPortAndPrivatePolicy("", true)

	// geosite:cn in blockList must NOT block unrelated domains containing "cn" like cnbc.com
	if d := eng.DecideForNode(1, "www.cnbc.com", 443, "", "tls"); d.Action != ActionDirect {
		t.Fatalf("unknown geosite:cn falsely blocked www.cnbc.com: %+v", d)
	}

	// Whitelisted private IP literal MUST pass even when ban_private_ip=true
	if d := eng.DecideForNode(1, "10.1.2.3", 443, "", ""); d.Action != ActionDirect || d.RuleName != "whitelist" || d.ForbidPrivate {
		t.Fatalf("whitelisted private IP 10.1.2.3 was blocked by ban_private_ip: %+v", d)
	}
	if d := eng.DecideForNode(1, "192.168.50.42", 443, "", ""); d.Action != ActionDirect || d.RuleName != "whitelist" {
		t.Fatalf("whitelisted private CIDR 192.168.50.42 was blocked by ban_private_ip: %+v", d)
	}
	// Non-whitelisted private IP MUST still be blocked
	if d := eng.DecideForNode(1, "10.9.9.9", 443, "", ""); d.Action != ActionBlock || d.RuleName != "ban-private-ip" {
		t.Fatalf("expected non-whitelisted private IP 10.9.9.9 to be blocked, got %+v", d)
	}

	// Unresolved [[routes]] outbound must be skipped (ActionDirect) instead of silently blackholing
	if d := eng.DecideForNode(1, "sub.example.org", 443, "", "tls"); d.Action != ActionDirect {
		t.Fatalf("unresolved [[routes]] outbound silently blackholed sub.example.org: %+v", d)
	}
}
