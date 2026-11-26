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
