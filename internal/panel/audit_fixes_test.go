package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xmg665/xoga/internal/config"
)

func TestH7N11UniProxyAndSSPanelFixes(t *testing.T) {
	// 1. UniProxy auto probe retries on HTTP 500, normalizes obfs="none", takes first CSV server_name for RealityDest,
	//    and decodes string/bool JSON values in uniUsersResp.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			nt := r.URL.Query().Get("node_type")
			if nt == "" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"node_type required"}`))
				return
			}
			if nt == "hysteria2" {
				_, _ = w.Write([]byte(`{
					"protocol":"hysteria2",
					"server_port":8443,
					"obfs":"none",
					"tls":2,
					"tls_settings":{
						"server_name":"www.apple.com, www.icloud.com",
						"server_port":443
					}
				}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/user"):
			_, _ = w.Write([]byte(`{
				"users":[
					{"id":1,"uuid":"u1","speed_limit":"100","device_limit":"3","banned":false,"expired_at":"4102444800"},
					{"id":2,"uuid":"u2","speed_limit":50.5,"device_limit":2,"banned":"1"},
					{"id":3,"uuid":"u3","speed_limit":null,"device_limit":"","banned":true},
					{"id":4,"uuid":"u4","speed_limit":"0","device_limit":"0","banned":"0"}
				]
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Type = "v2board"
	cfg.ServerType = "auto"
	cfg.NodeID = 10
	cfg.WebAPIURL = srv.URL
	cfg.WebAPIKey = "super-secret-api-key-999"

	cli := NewUniProxyClient(cfg, srv.Client())
	spec, err := cli.FetchNodeConfig(context.Background())
	if err != nil {
		t.Fatalf("UniProxy auto probe on HTTP 500 failed: %v", err)
	}
	if spec.Hy2Obfs != "" || spec.Hy2ObfsPassword != "" {
		t.Fatalf("expected obfs=\"none\" normalized to empty, got obfs=%q pw=%q", spec.Hy2Obfs, spec.Hy2ObfsPassword)
	}
	if spec.RealityDest != "www.apple.com:443" {
		t.Fatalf("expected first CSV hostname for RealityDest, got %q", spec.RealityDest)
	}
	if len(spec.RealityServerNames) != 2 || spec.RealityServerNames[0] != "www.apple.com" || spec.RealityServerNames[1] != "www.icloud.com" {
		t.Fatalf("unexpected RealityServerNames: %v", spec.RealityServerNames)
	}

	users, err := cli.FetchUsers(context.Background())
	if err != nil {
		t.Fatalf("FetchUsers string/bool tolerance failed: %v", err)
	}
	if len(users) != 2 || users[0].ID != 1 || users[0].DeviceLimit != 3 || users[0].SpeedLimit != 100*125000 || users[1].ID != 4 {
		t.Fatalf("unexpected parsed users: %+v", users)
	}

	// 2. NewRequestWithContext error redaction (must never leak WebAPIKey!)
	badCfg := config.Default()
	badCfg.WebAPIURL = "http://[::1]:badport\n"
	badCfg.WebAPIKey = "TOPSECRET_TOKEN_XYZ"
	badCli := NewUniProxyClient(badCfg, srv.Client())
	if _, err := badCli.FetchNodeConfig(context.Background()); err == nil {
		t.Fatal("expected error for malformed URL")
	} else if strings.Contains(err.Error(), "TOPSECRET_TOKEN_XYZ") {
		t.Fatalf("NewRequestWithContext error leaked WebAPIKey: %v", err)
	}
	badSS := NewSSPanelClient(badCfg, srv.Client())
	if _, err := badSS.FetchNodeConfig(context.Background()); err == nil {
		t.Fatal("expected error for malformed SSPanel URL")
	} else if strings.Contains(err.Error(), "TOPSECRET_TOKEN_XYZ") {
		t.Fatalf("SSPanel NewRequestWithContext error leaked WebAPIKey: %v", err)
	}

	// 3. parseMetronServerString IPv6 support
	sp1 := &NodeSpec{}
	parseMetronServerString("[2001:db8::1]:8443;0;ws;;path=/v6|obfs=plain", sp1)
	if sp1.ServerPort != 8443 || sp1.Hy2Obfs != "" || sp1.ServerName != "" {
		t.Fatalf("parseMetronServerString bracketed IPv6 failed: port=%d obfs=%q sni=%q", sp1.ServerPort, sp1.Hy2Obfs, sp1.ServerName)
	}
	sp2 := &NodeSpec{}
	parseMetronServerString("2001:db8::2;443;0;tcp", sp2)
	if sp2.ServerPort != 443 || sp2.ServerName != "" {
		t.Fatalf("parseMetronServerString bare IPv6 failed: port=%d sni=%q", sp2.ServerPort, sp2.ServerName)
	}
}
