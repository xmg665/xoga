package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndUpdateFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "xoga.conf")
	applied, err := UpdateFile(tmp, []string{
		"type=xboard",
		"server_type=trojan",
		"node_id=12",
		"webapi_url=https://panel.example.com/",
		"webapi_key=my_secret_key",
		"dy_limit_white_user_id=1,5,9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 6 {
		t.Fatalf("expected 6 applied keys, got %d", len(applied))
	}

	cfg, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.NodeID != 12 || cfg.WebAPIURL != "https://panel.example.com" || cfg.NormalizedPanelType() != "uniproxy" {
		t.Fatalf("unexpected loaded config: %+v", cfg)
	}
	if _, ok := cfg.DyLimitWhiteUserIDs[5]; !ok {
		t.Fatalf("expected whitelist user 5")
	}
	if cfg.DeviceLimitEnable {
		t.Fatalf("expected DeviceLimitEnable=false by default")
	}
	cfg.ApplyKV("device_limit_enable", "true")
	if !cfg.DeviceLimitEnable {
		t.Fatalf("expected device_limit_enable=true to enable DeviceLimitEnable")
	}
	cfg.ApplyKV("device_limit_enable", "false")
	if cfg.DeviceLimitEnable {
		t.Fatalf("expected device_limit_enable=false to disable DeviceLimitEnable")
	}
	_ = os.Remove(tmp)
}

func TestMultiNodeIDAndDockerEnv(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "soga.conf")
	raw := `
type=sspanel-uim
server_type=v2ray
node_id=781,782,783-785,782,911
webapi_url=https://api.example.com/
webapi_key=testkey
proxy_protocol=true
forward_extra_port_enable=true
log_level=false
`
	if err := os.WriteFile(tmp, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate multi-node failed: %v", err)
	}
	wantIDs := []int{781, 782, 783, 784, 785, 911}
	gotIDs := cfg.EffectiveNodeIDs()
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("expected %v, got %v", wantIDs, gotIDs)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("mismatch at %d: want %d got %d", i, wantIDs[i], gotIDs[i])
		}
	}
	if cfg.FormatNodeIDs() != "781,782,783(+3)" {
		t.Fatalf("unexpected FormatNodeIDs: %s", cfg.FormatNodeIDs())
	}

	// Verify IS_DOCKER=true env-only bootstrap without a config file on disk
	t.Setenv("IS_DOCKER", "true")
	t.Setenv("type", "sspanel-uim")
	t.Setenv("server_type", "v2ray")
	t.Setenv("node_id", "851")
	t.Setenv("webapi_url", "https://api.example.com/")
	t.Setenv("webapi_key", "docker-key")
	t.Setenv("proxy_protocol", "true")

	envCfg, err := LoadWithEnv(filepath.Join(t.TempDir(), "nonexistent.conf"))
	if err != nil {
		t.Fatalf("LoadWithEnv docker mode failed: %v", err)
	}
	if envCfg.NodeID != 851 || !envCfg.ProxyProtocol || envCfg.NormalizedServerType() != "vmess" {
		t.Fatalf("unexpected docker env config: %+v", envCfg)
	}

	// Verify default ServerType is "auto" (auto-detected from panel)
	defCfg := Default()
	if defCfg.ServerType != "auto" || defCfg.NormalizedServerType() != "auto" {
		t.Fatalf("expected Default().ServerType=auto, got %q (%q)", defCfg.ServerType, defCfg.NormalizedServerType())
	}
	defCfg.NodeID = 1
	defCfg.NodeIDs = []int{1}
	defCfg.WebAPIURL = "https://panel.example.com"
	defCfg.WebAPIKey = "tok"
	if err := defCfg.Validate(); err != nil {
		t.Fatalf("expected server_type=auto to pass Validate(), got %v", err)
	}

	// Verify uppercase `NODE_ID` env var & empty `reality_short_ids=` not producing `[""]`
	t.Setenv("node_id", "")
	t.Setenv("NODE_ID", "999")
	upperCfg, err := LoadWithEnv(filepath.Join(t.TempDir(), "missing2.conf"))
	if err != nil || upperCfg.NodeID != 999 {
		t.Fatalf("expected uppercase NODE_ID=999 to be honored, got NodeID=%d err=%v", upperCfg.NodeID, err)
	}
	upperCfg.ApplyKV("reality_short_ids", "")
	if len(upperCfg.RealityShortIDs) != 0 {
		t.Fatalf("empty reality_short_ids= must leave slice empty, got %v", upperCfg.RealityShortIDs)
	}
}

func TestTrustedProxyCIDRsAndGCPercentSet(t *testing.T) {
	// Default config must NOT mark GCPercentSet=true so v2ray_reduce_memory can tune default 100 -> 75.
	def := Default()
	if def.GCPercent != 100 || def.GCPercentSet {
		t.Fatalf("unexpected default GCPercent=%d GCPercentSet=%v", def.GCPercent, def.GCPercentSet)
	}

	tmp := filepath.Join(t.TempDir(), "xoga.conf")
	raw := `
type=sspanel
node_id=781
webapi_url=https://panel.example.com
webapi_key=k
v2ray_reduce_memory=true
gc_percent=100
trusted_proxy_cidrs=203.175.12.253, 172.64.0.0/13, 2606:4700::/32
`
	if err := os.WriteFile(tmp, []byte(raw), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GCPercentSet || cfg.GCPercent != 100 {
		t.Fatalf("explicit gc_percent=100 must set GCPercentSet=true, got %d (%v)", cfg.GCPercent, cfg.GCPercentSet)
	}
	wantCIDRs := []string{"203.175.12.253", "172.64.0.0/13", "2606:4700::/32"}
	if len(cfg.TrustedProxyCIDRs) != len(wantCIDRs) {
		t.Fatalf("TrustedProxyCIDRs mismatch: got %v want %v", cfg.TrustedProxyCIDRs, wantCIDRs)
	}
	for i := range wantCIDRs {
		if cfg.TrustedProxyCIDRs[i] != wantCIDRs[i] {
			t.Fatalf("TrustedProxyCIDRs[%d]=%q want %q", i, cfg.TrustedProxyCIDRs[i], wantCIDRs[i])
		}
	}

	// Verify env var override for TRUSTED_PROXY_CIDRS and XOGA_GC_PERCENT
	t.Setenv("TRUSTED_PROXY_CIDRS", "43.217.251.51/32,103.147.198.84")
	t.Setenv("XOGA_GC_PERCENT", "120")
	cfg.ApplyEnv()
	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[0] != "43.217.251.51/32" || cfg.TrustedProxyCIDRs[1] != "103.147.198.84" {
		t.Fatalf("env override for trusted_proxy_cidrs failed: %v", cfg.TrustedProxyCIDRs)
	}
	if cfg.GCPercent != 120 || !cfg.GCPercentSet {
		t.Fatalf("env override for XOGA_GC_PERCENT failed: %d (%v)", cfg.GCPercent, cfg.GCPercentSet)
	}

	// CloneForNode must preserve GCPercentSet and TrustedProxyCIDRs
	cloned := cfg.CloneForNode(782)
	if !cloned.GCPercentSet || len(cloned.TrustedProxyCIDRs) != 2 {
		t.Fatalf("CloneForNode dropped GCPercentSet or TrustedProxyCIDRs: %+v", cloned)
	}
}
