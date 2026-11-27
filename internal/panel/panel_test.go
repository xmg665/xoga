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

func TestPanelAutoProtocolDetectionSSPanelAndUniProxy(t *testing.T) {
	// 1. SSPanel with server_type=auto (and even server_type=v2ray) must detect VMess(11), VLESS(18), VLESS-REALITY(18), Hy2(15), Trojan(14), SS(0) from panel!
	ssMux := http.NewServeMux()
	ssMux.HandleFunc("/mod_mu/nodes/781/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"sort":11,"method":"None","server":"hk5.v2api.xyz;2001;0;ws;;path=/mm|host=aomen.kugou.com"}}`))
	})
	ssMux.HandleFunc("/mod_mu/nodes/916/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"sort":18,"method":"None","server":"apple.apple9.org;2086;0;ws;;path=/mm|host=xg2.apple9.org"}}`))
	})
	ssMux.HandleFunc("/mod_mu/nodes/948/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"sort":18,"method":"None","server":"chun31.apple9.org;443;0;tcp;tls;publicKey=pub|privateKey=SPUSt4KA8qnkfgzWqnNmnAfxmkqGJsHHSXqCQE8RvnY|shortId=8d500d61|flow=xtls-rprx-vision|host=www.microsoft.com"}}`))
	})
	ssMux.HandleFunc("/mod_mu/nodes/972/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ret":1,"data":{"sort":15,"method":"None","server":"jp5.help600.com;port=443|ports=444-8443|up=1000|down=500|obfs=salamander|obfs-password=sec"}}`))
	})
	ssSrv := httptest.NewServer(ssMux)
	defer ssSrv.Close()

	checkSS := func(nodeID int) *NodeSpec {
		c := config.Default() // ServerType == "auto"
		c.Type = "sspanel-uim"
		c.NodeID = nodeID
		c.NodeIDs = []int{nodeID}
		c.WebAPIURL = ssSrv.URL
		c.WebAPIKey = "k"
		cli, err := NewClient(c)
		if err != nil {
			t.Fatal(err)
		}
		sp, err := cli.FetchNodeConfig(context.Background())
		if err != nil {
			t.Fatalf("node %d FetchNodeConfig failed: %v", nodeID, err)
		}
		return sp
	}

	if sp := checkSS(781); sp.Protocol != "vmess" || sp.ServerPort != 2001 || sp.Network != "ws" {
		t.Fatalf("node 781 expected vmess/ws:2001, got %+v", sp)
	}
	if sp := checkSS(916); sp.Protocol != "vless" || sp.ServerPort != 2086 || sp.Network != "ws" {
		t.Fatalf("node 916 expected vless/ws:2086, got %+v", sp)
	}
	if sp := checkSS(948); sp.Protocol != "vless" || sp.TLSMode != 2 || sp.RealityPrivateKey == "" || sp.RealityDest != "www.microsoft.com:443" || len(sp.RealityShortIDs) != 1 || sp.Flow != "xtls-rprx-vision" {
		t.Fatalf("node 948 expected vless-reality dest=www.microsoft.com:443, got %+v", sp)
	}
	if sp := checkSS(972); sp.Protocol != "hysteria2" || sp.Network != "quic" || sp.TLSMode != 1 || sp.ServerName != "jp5.help600.com" || sp.Hy2UpMbps != 1000 || sp.Hy2DownMbps != 500 || sp.Hy2ObfsPassword != "sec" {
		t.Fatalf("node 972 expected hysteria2 sni=jp5.help600.com 1000/500Mbps, got %+v", sp)
	}

	// 2. UniProxy with server_type=auto when panel requires `node_type=trojan` -> auto-probes & latches!
	uniSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("node_type") != "trojan" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/api/v1/server/UniProxy/config" {
			_, _ = w.Write([]byte(`{"protocol":"trojan","server_port":1443,"tls":1,"server_name":"tr.example.com"}`))
			return
		}
		_, _ = w.Write([]byte(`{"users":[{"id":9,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}`))
	}))
	defer uniSrv.Close()

	uc := config.Default() // ServerType == "auto"
	uc.Type = "v2board"
	uc.NodeID = 3
	uc.NodeIDs = []int{3}
	uc.WebAPIURL = uniSrv.URL
	uc.WebAPIKey = "tok"
	ucli, _ := NewClient(uc)
	usp, err := ucli.FetchNodeConfig(context.Background())
	if err != nil || usp.Protocol != "trojan" || usp.ServerPort != 1443 {
		t.Fatalf("expected UniProxy auto-probe to discover trojan:1443, got %+v err=%v", usp, err)
	}
	uusers, err := ucli.FetchUsers(context.Background())
	if err != nil || len(uusers) != 1 {
		t.Fatalf("expected latched node_type=trojan on FetchUsers, got %+v err=%v", uusers, err)
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

func TestPanelRedirectPolicyAndTruncateMsg(t *testing.T) {
	if got := truncateMsg([]byte("<html>\r\n<head><title>405 Not Allowed</title></head>\n<body>405</body>\n</html>")); got != "<html> <head><title>405 Not Allowed</title></head> <body>405</body> </html>" {
		t.Fatalf("truncateMsg did not collapse newlines: %q", got)
	}

	cli := NewKeepAliveHTTPClient(2)

	// Same-host redirect should be followed cleanly without sending Referer
	var sawReferer string
	sameHostSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
			return
		}
		sawReferer = r.Header.Get("Referer")
		_, _ = w.Write([]byte("ok"))
	}))
	defer sameHostSrv.Close()

	resp, err := cli.Get(sameHostSrv.URL + "/old?key=secret")
	if err != nil {
		t.Fatalf("same-host redirect failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after same-host redirect, got %d", resp.StatusCode)
	}
	if sawReferer != "" {
		t.Fatalf("expected empty Referer on redirect, got %q", sawReferer)
	}

	// Cross-host redirect must NOT be followed
	crossSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/steal", http.StatusFound)
	}))
	defer crossSrv.Close()

	resp2, err := cli.Get(crossSrv.URL + "/start?key=secret")
	if err != nil {
		t.Fatalf("cross-host redirect returned unexpected err: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (not followed) on cross-host redirect, got %d", resp2.StatusCode)
	}
}
