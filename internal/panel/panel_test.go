package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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

func TestUniProxyTransient500AndExpiryBypassETag(t *testing.T) {
	var failConfig atomic.Bool
	failConfig.Store(true)
	expSoon := time.Now().Unix() + 1

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nt := r.URL.Query().Get("node_type")
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if failConfig.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if nt != "vmess" {
				// Modern Xboard rejecting legacy "v2ray"
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"protocol":"vmess","server_port":2008,"network":"ws"}`))
		case "/api/v1/server/UniProxy/user":
			if r.Header.Get("If-None-Match") == `"const-etag"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"const-etag"`)
			_, _ = w.Write([]byte(`{"users":[{"id":1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","expired_at":` + strconv.FormatInt(expSoon, 10) + `},{"id":2,"uuid":"c942492e-7435-4e64-be50-9deb59c41922"}]}`))
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Type = "xboard"
	cfg.ServerType = "vmess"
	cfg.NodeID = 1
	cfg.WebAPIURL = srv.URL
	cfg.WebAPIKey = "tok"

	cli, _ := NewClient(cfg)
	ctx := context.Background()

	// 1. Transient HTTP 500 on both primary and fallback must NOT poison node_type to "v2ray"
	if _, err := cli.FetchNodeConfig(ctx); err == nil {
		t.Fatal("expected error during HTTP 500 outage")
	}
	failConfig.Store(false)
	if _, err := cli.FetchNodeConfig(ctx); err != nil {
		t.Fatalf("expected recovery with node_type=vmess after transient 500, got: %v", err)
	}

	// 2. Wall-clock ExpiredAt arrival must bypass ETag/bodyHash short-circuit and drop expired user 1
	u1, err := cli.FetchUsers(ctx)
	if err != nil || len(u1) != 2 {
		t.Fatalf("expected 2 initial users, got %d err=%v", len(u1), err)
	}
	time.Sleep(1100 * time.Millisecond)
	u2, err := cli.FetchUsers(ctx)
	if err != nil {
		t.Fatalf("expected wall-clock expiry re-evaluation instead of ErrNotModified, got err=%v", err)
	}
	if len(u2) != 1 || u2[0].ID != 2 {
		t.Fatalf("expected expired user 1 to be filtered out, got %+v", u2)
	}
}

func TestSSPanelTrafficRateQuotaScaling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mod_mu/nodes/781/info":
			_, _ = w.Write([]byte(`{"ret":1,"data":{"node_speedlimit":0,"node_connector":0,"traffic_rate":0.2,"server":"hk.example.com;2001;0;ws;;path=/ws","sort":11}}`))
		case "/mod_mu/users":
			_, _ = w.Write([]byte(`{"ret":1,"data":[{"id":5,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","passwd":"pw","enable":1,"u":0,"d":0,"transfer_enable":1000}]}`))
		default:
			_, _ = w.Write([]byte(`{"ret":1,"data":[]}`))
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Type = "sspanel"
	cfg.ServerType = "vmess"
	cfg.NodeID = 781
	cfg.WebAPIURL = srv.URL
	cfg.WebAPIKey = "mukey"

	cli, _ := NewClient(cfg)
	ctx := context.Background()
	if _, err := cli.FetchNodeConfig(ctx); err != nil {
		t.Fatal(err)
	}
	users, err := cli.FetchUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("fetch users failed: %v", err)
	}
	// 1000 panel bytes on a 0.2x node => 5000 real node bytes!
	if users[0].RemainBytes != 5000 {
		t.Fatalf("expected scaled RemainBytes=5000 for traffic_rate=0.2, got %d", users[0].RemainBytes)
	}
}

func TestSSPanelDualCredentialsAndUniProxyAliveSumFixes(t *testing.T) {
	// 1. SSPanel user with BOTH uuid and passwd must preserve passwd in AltPasswd (fixing Shadowsocks auth!)
	ssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mod_mu/nodes/1/info":
			_, _ = w.Write([]byte(`{"ret":1,"data":{"method":"aes-256-gcm","server":"1.1.1.1;8388","sort":0}}`))
		case "/mod_mu/users":
			_, _ = w.Write([]byte(`{"ret":1,"data":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","passwd":"real-ss-password","enable":1,"u":0,"d":0,"transfer_enable":10000}]}`))
		default:
			_, _ = w.Write([]byte(`{"ret":1,"data":[]}`))
		}
	}))
	defer ssSrv.Close()

	ssCfg := config.Default()
	ssCfg.Type = "sspanel"
	ssCfg.ServerType = "ss"
	ssCfg.NodeID = 1
	ssCfg.WebAPIURL = ssSrv.URL
	ssCfg.WebAPIKey = "k"
	ssCli, _ := NewClient(ssCfg)
	specs, err := ssCli.FetchUsers(context.Background())
	if err != nil || len(specs) != 1 {
		t.Fatalf("FetchUsers failed: %v", err)
	}
	tr := stats.NewTracker(ssCfg)
	entries, _, _, _ := tr.ReconcileUsers(specs)
	if entries[0].Passwd != "real-ss-password" || entries[0].UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("SSPanel dual credentials corrupted: UUID=%q Passwd=%q", entries[0].UUID, entries[0].Passwd)
	}

	// 2. UniProxy: `server_type=v2ray` auto-negotiates `vmess` on modern Xboard, sums duplicate UserID deltas in PushTraffic,
	//    and parses Xboard integer `/alivelist` counts!
	var gotSum [2]int64
	uniSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/server/UniProxy/config":
			if r.URL.Query().Get("node_type") != "vmess" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"protocol":"vmess","server_port":12345}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{"101":2}}`))
		case "/api/v1/server/UniProxy/push":
			var m map[string][2]int64
			_ = json.NewDecoder(r.Body).Decode(&m)
			gotSum = m["101"]
			_, _ = w.Write([]byte(`{"data":true}`))
		}
	}))
	defer uniSrv.Close()

	uCfg := config.Default()
	uCfg.Type = "xboard"
	uCfg.ServerType = "v2ray" // legacy soga setting against modern Xboard!
	uCfg.NodeID = 1
	uCfg.WebAPIURL = uniSrv.URL
	uCfg.WebAPIKey = "tok"
	uCli, _ := NewClient(uCfg)
	if _, err := uCli.FetchNodeConfig(context.Background()); err != nil {
		t.Fatalf("expected server_type=v2ray -> vmess negotiation to succeed, got %v", err)
	}
	alive, err := uCli.FetchAliveList(context.Background())
	if err != nil || alive == nil || alive.Counts[101] != 2 {
		t.Fatalf("expected Xboard integer alive count 2 for user 101, got %+v err=%v", alive, err)
	}
	_ = uCli.PushTraffic(context.Background(), []stats.TrafficDelta{
		{UserID: 101, Upload: 1000, Download: 2000},
		{UserID: 101, Upload: 500, Download: 300},
	})
	if gotSum != [2]int64{1500, 2300} {
		t.Fatalf("expected summed traffic [1500, 2300], got %+v", gotSum)
	}
}
