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
