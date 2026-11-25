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
	_ = os.Remove(tmp)
}
