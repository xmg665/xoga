package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

func TestNEW3SSPanelDetectRulesSharedKeySingleflightAndChangePropagation(t *testing.T) {
	var detectHits atomic.Int32
	var ruleVersion atomic.Int32
	ruleVersion.Store(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/mod_mu/nodes/") && strings.HasSuffix(r.URL.Path, "/info"):
			if r.Header.Get("If-None-Match") == `"node-v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"node-v1"`)
			_, _ = w.Write([]byte(`{"ret":1,"data":{"server":"node.example.com;2001;0;ws;;path=/ws","sort":11,"traffic_rate":1}}`))
		case r.URL.Path == "/mod_mu/func/detect_rules":
			detectHits.Add(1)
			time.Sleep(30 * time.Millisecond) // allow all 20 goroutines to coalesce in singleflight
			if ruleVersion.Load() == 1 {
				_, _ = w.Write([]byte(`{"ret":1,"data":[{"regex":"^bad1\\.example\\.com$","type":1}]}`))
			} else {
				_, _ = w.Write([]byte(`{"ret":1,"data":[{"regex":"^bad1\\.example\\.com$","type":1},{"regex":"^bad2\\.example\\.com$","type":1}]}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Create 20 SSPanelClient instances for nodes 781..800 sharing the same panel URL + WebAPIKey.
	const numNodes = 20
	clients := make([]*SSPanelClient, numNodes)
	for i := 0; i < numNodes; i++ {
		cfg := config.Default()
		cfg.Type = "sspanel"
		cfg.NodeID = 781 + i
		cfg.WebAPIURL = srv.URL
		cfg.WebAPIKey = "shared-panel-key-new3"
		clients[i] = NewSSPanelClient(cfg, srv.Client())
	}

	// 1. Concurrent initial FetchNodeConfig across all 20 nodes -> ONLY 1 HTTP GET to /mod_mu/func/detect_rules!
	var wg sync.WaitGroup
	errs := make(chan error, numNodes)
	for i := 0; i < numNodes; i++ {
		wg.Add(1)
		go func(c *SSPanelClient) {
			defer wg.Done()
			spec, err := c.FetchNodeConfig(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if len(spec.Routes) != 1 || len(spec.Routes[0].Matches) != 1 || spec.Routes[0].Matches[0] != "regexp:^bad1\\.example\\.com$" {
				errs <- context.DeadlineExceeded
			}
		}(clients[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("initial multi-node FetchNodeConfig failed: %v", err)
	}
	if got := detectHits.Load(); got != 1 {
		t.Fatalf("expected exactly 1 /mod_mu/func/detect_rules HTTP GET across %d concurrent nodes, got %d", numNodes, got)
	}

	// 2. Subsequent 304 poll while cache is fresh -> ErrNotModified and 0 extra HTTP GETs.
	for i := 0; i < numNodes; i++ {
		if _, err := clients[i].FetchNodeConfig(context.Background()); err != ErrNotModified {
			t.Fatalf("node %d expected ErrNotModified while cache fresh, got %v", i, err)
		}
	}
	if got := detectHits.Load(); got != 1 {
		t.Fatalf("expected 0 extra detect_rules fetches while fresh, got total %d", got)
	}

	// 3. Expire shared cache and update rules on panel -> ALL 20 nodes must observe the updated rules
	//    even on 304 node info, with ONLY 1 new HTTP GET!
	ruleVersion.Store(2)
	cacheKey := clients[0].detectCacheKey()
	detectCacheMu.Lock()
	ce := detectCache[cacheKey]
	ce.expires = time.Now().Unix() - 1
	detectCache[cacheKey] = ce
	detectCacheMu.Unlock()

	for i := 0; i < numNodes; i++ {
		spec, err := clients[i].FetchNodeConfig(context.Background())
		if err != nil {
			t.Fatalf("node %d failed to pick up updated shared detect_rules after cache expiry: %v", i, err)
		}
		if len(spec.Routes) != 1 || len(spec.Routes[0].Matches) != 2 {
			t.Fatalf("node %d did not receive 2 updated detect_rules: %+v", i, spec.Routes)
		}
	}
	if got := detectHits.Load(); got != 2 {
		t.Fatalf("expected exactly 2 total detect_rules HTTP GETs after refresh across %d nodes, got %d", numNodes, got)
	}

	// 4. Next poll across all 20 nodes -> all settled on v2 -> ErrNotModified and 0 extra GETs.
	for i := 0; i < numNodes; i++ {
		if _, err := clients[i].FetchNodeConfig(context.Background()); err != ErrNotModified {
			t.Fatalf("node %d expected ErrNotModified after settling on v2, got %v", i, err)
		}
	}
	if got := detectHits.Load(); got != 2 {
		t.Fatalf("expected 2 total detect_rules HTTP GETs after settling, got %d", got)
	}
}

func TestPanelPostValidatesBodyPreventsSilentTrafficLossAndRedactsSecrets(t *testing.T) {
	batch := []stats.TrafficDelta{{UserID: 101, Upload: 2048, Download: 4096}}

	t.Run("SSPanelPostRejectsRet0AndHTML200", func(t *testing.T) {
		var mode atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			switch mode.Load() {
			case 0:
				_, _ = w.Write([]byte(`{"ret":0,"data":"invalid key"}`))
			case 1:
				_, _ = w.Write([]byte(`<html><body>502 Maintenance https://panel.test/mod_mu/users/traffic?key=TOPSECRETKEY99&node_id=851</body></html>`))
			case 2:
				_, _ = w.Write([]byte(`Connection refused`))
			case 3:
				_, _ = w.Write([]byte(`{"ret":1,"data":"ok"}`))
			case 4:
				// empty 200 body (compatible with minimal mocks)
			}
		}))
		defer srv.Close()

		cfg := config.Default()
		cfg.Type = "sspanel"
		cfg.NodeID = 851
		cfg.WebAPIURL = srv.URL
		cfg.WebAPIKey = "TOPSECRETKEY99"
		cli := NewSSPanelClient(cfg, srv.Client())

		// ret=0 on HTTP 200 -> MUST fail so daemon rolls back traffic!
		mode.Store(0)
		if err := cli.PushTraffic(context.Background(), batch); err == nil || !strings.Contains(err.Error(), "ret=0") {
			t.Fatalf("expected ret=0 error on HTTP 200, got %v", err)
		}

		// HTML maintenance page on HTTP 200 -> MUST fail AND redact echoed secret key!
		mode.Store(1)
		err := cli.PushTraffic(context.Background(), batch)
		if err == nil {
			t.Fatal("expected error on HTTP 200 HTML response")
		}
		if strings.Contains(err.Error(), "TOPSECRETKEY99") {
			t.Fatalf("secret WebAPI key leaked in error snippet: %v", err)
		}
		if !strings.Contains(err.Error(), "key=***") {
			t.Fatalf("expected redacted key=*** in error snippet, got %v", err)
		}

		// Plain non-JSON error text on HTTP 200 -> MUST fail!
		mode.Store(2)
		if err := cli.PushTraffic(context.Background(), batch); err == nil {
			t.Fatal("expected error on HTTP 200 non-JSON body")
		}

		// Standard SSPanel ret=1 -> MUST succeed!
		mode.Store(3)
		if err := cli.PushTraffic(context.Background(), batch); err != nil {
			t.Fatalf("expected ret=1 to succeed, got %v", err)
		}

		// Empty 200 body -> MUST succeed!
		mode.Store(4)
		if err := cli.PushTraffic(context.Background(), batch); err != nil {
			t.Fatalf("expected empty 200 body to succeed, got %v", err)
		}
	})

	t.Run("UniProxyPostAndAliveListRejectHTML200AndFalse", func(t *testing.T) {
		var mode atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if strings.HasSuffix(r.URL.Path, "/alivelist") {
				switch mode.Load() {
				case 0:
					_, _ = w.Write([]byte(`<html><title>CF Challenge</title></html>`))
				case 1:
					_, _ = w.Write([]byte(`{"alive":[]}`))
				}
				return
			}
			switch mode.Load() {
			case 0:
				_, _ = w.Write([]byte(`<html><body>WAF block /api?token=UNIPROXYSECRET&node_id=1</body></html>`))
			case 1:
				_, _ = w.Write([]byte(`{"data":false,"message":"denied"}`))
			case 2:
				_, _ = w.Write([]byte(`false`))
			case 3:
				_, _ = w.Write([]byte(`{"data":true}`))
			}
		}))
		defer srv.Close()

		cfg := config.Default()
		cfg.Type = "xboard"
		cfg.ServerType = "vless"
		cfg.NodeID = 1
		cfg.WebAPIURL = srv.URL
		cfg.WebAPIKey = "UNIPROXYSECRET"
		cli := NewUniProxyClient(cfg, srv.Client())

		mode.Store(0)
		err := cli.PushTraffic(context.Background(), batch)
		if err == nil {
			t.Fatal("expected error on UniProxy HTTP 200 HTML response")
		}
		if strings.Contains(err.Error(), "UNIPROXYSECRET") {
			t.Fatalf("secret UniProxy token leaked in error snippet: %v", err)
		}
		if _, aerr := cli.FetchAliveList(context.Background()); aerr == nil {
			t.Fatal("expected FetchAliveList to return error on HTTP 200 HTML instead of empty AliveList")
		}

		mode.Store(1)
		if err := cli.PushTraffic(context.Background(), batch); err == nil {
			t.Fatal("expected error on UniProxy {\"data\":false}")
		}
		if al, aerr := cli.FetchAliveList(context.Background()); aerr != nil || al == nil {
			t.Fatalf("expected valid empty {\"alive\":[]} to return non-nil empty AliveList, got al=%v err=%v", al, aerr)
		}

		mode.Store(2)
		if err := cli.PushTraffic(context.Background(), batch); err == nil {
			t.Fatal("expected error on UniProxy bare false")
		}

		mode.Store(3)
		if err := cli.PushTraffic(context.Background(), batch); err != nil {
			t.Fatalf("expected UniProxy {\"data\":true} to succeed, got %v", err)
		}
	})
}
