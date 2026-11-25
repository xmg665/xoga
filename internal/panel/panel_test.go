package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

func TestUniProxyETagAndTrafficPush(t *testing.T) {
	var pushed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if r.Header.Get("If-None-Match") == `"cfg-etag-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"cfg-etag-1"`)
			_, _ = w.Write([]byte(`{"protocol":"vless","server_port":20443,"network":"ws","networkSettings":{"path":"/vless"},"tls":1,"server_name":"hk.example.com","base_config":{"push_interval":45,"pull_interval":30}}`))
		case "/api/v1/server/UniProxy/user":
			if r.Header.Get("If-None-Match") == `"usr-etag-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"usr-etag-1"`)
			_, _ = w.Write([]byte(`{"users":[{"id":101,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":50,"device_limit":3}]}`))
		case "/api/v1/server/UniProxy/push":
			var body map[string][2]int64
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode push body: %v", err)
			}
			if body["101"] != [2]int64{1024, 4096} {
				t.Errorf("unexpected traffic map: %+v", body)
			}
			pushed.Add(1)
			_, _ = w.Write([]byte(`{"data":true}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Type = "xboard"
	cfg.ServerType = "vless"
	cfg.NodeID = 1
	cfg.WebAPIURL = srv.URL
	cfg.WebAPIKey = "secret-token"

	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	spec, err := cli.FetchNodeConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if spec.ServerPort != 20443 || spec.WSPath != "/vless" || spec.PullInterval != 30 {
		t.Fatalf("unexpected spec: %+v", spec)
	}

	// Second call must hit ETag 304 short-circuit
	if _, err := cli.FetchNodeConfig(ctx); !errors.Is(err, ErrNotModified) {
		t.Fatalf("expected ErrNotModified on second FetchNodeConfig, got %v", err)
	}

	users, err := cli.FetchUsers(ctx)
	if err != nil || len(users) != 1 || users[0].ID != 101 {
		t.Fatalf("unexpected users: %+v, err=%v", users, err)
	}
	if _, err := cli.FetchUsers(ctx); !errors.Is(err, ErrNotModified) {
		t.Fatalf("expected ErrNotModified on second FetchUsers, got %v", err)
	}

	if err := cli.PushTraffic(ctx, []stats.TrafficDelta{{UserID: 101, Upload: 1024, Download: 4096}}); err != nil {
		t.Fatal(err)
	}
	if pushed.Load() != 1 {
		t.Fatalf("expected 1 push call, got %d", pushed.Load())
	}
}

func TestSSPanelMetronStringParser(t *testing.T) {
	spec := &NodeSpec{Protocol: "trojan", Network: "tcp"}
	parseMetronServerString("jp01.node.com;port=443#18443;ws;tls;path=/trojan-ws;host=cdn.node.com", spec)
	if spec.ServerPort != 18443 || spec.Network != "ws" || spec.TLSMode != 1 || spec.WSPath != "/trojan-ws" || spec.ServerName != "cdn.node.com" {
		t.Fatalf("unexpected parsed Metron spec: %+v", spec)
	}

	// Real SSPanel-UIM v3 mod_Uim sort=11 pipe-separated server string
	specUIM := &NodeSpec{Protocol: "vmess", Network: "tcp"}
	parseMetronServerString("hk5.v2api.xyz;2001;0;ws;;path=/mm|server=news2.help600.com|host=aomen.kugou.com|outside_port=20001", specUIM)
	if specUIM.ServerPort != 2001 || specUIM.Network != "ws" || specUIM.WSPath != "/mm" || specUIM.WSHost != "aomen.kugou.com" {
		t.Fatalf("unexpected parsed SSPanel-UIM pipe spec: %+v", specUIM)
	}
}
