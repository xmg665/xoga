package daemon

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/stats"
)

type fakePanelClient struct {
	spec  *panel.NodeSpec
	users []stats.SyncUserSpec

	fetchConfigCalls atomic.Int32
	fetchUsersCalls  atomic.Int32
	pushTrafficCalls atomic.Int32
	pushAliveCalls   atomic.Int32
	pushStatusCalls  atomic.Int32

	mu            sync.Mutex
	pushedUp      int64
	pushedDown    int64
	pushTrafficFn func(ctx context.Context, batch []stats.TrafficDelta) error
}

func (f *fakePanelClient) Name() string { return "fake" }

func (f *fakePanelClient) ClearNodeConfigETag() {}

func (f *fakePanelClient) FetchNodeConfig(ctx context.Context) (*panel.NodeSpec, error) {
	f.fetchConfigCalls.Add(1)
	f.mu.Lock()
	sp := f.spec
	f.mu.Unlock()
	return sp, nil
}

func (f *fakePanelClient) FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error) {
	f.fetchUsersCalls.Add(1)
	return f.users, nil
}

func (f *fakePanelClient) FetchAliveList(ctx context.Context) (*panel.AliveList, error) {
	return nil, nil
}

func (f *fakePanelClient) PushTraffic(ctx context.Context, batch []stats.TrafficDelta) error {
	f.pushTrafficCalls.Add(1)
	if f.pushTrafficFn != nil {
		if err := f.pushTrafficFn(ctx, batch); err != nil {
			return err
		}
	}
	f.mu.Lock()
	for _, r := range batch {
		f.pushedUp += r.Upload
		f.pushedDown += r.Download
	}
	f.mu.Unlock()
	return nil
}

func (f *fakePanelClient) PushAlive(ctx context.Context, alive map[int][]string) error {
	f.pushAliveCalls.Add(1)
	return nil
}

func (f *fakePanelClient) PushStatus(ctx context.Context, st panel.SystemStatus) error {
	f.pushStatusCalls.Add(1)
	return nil
}

func TestBUG8SharedACLPoolSharesEngineAcrossNodesAndPrunesOldSignatures(t *testing.T) {
	pool := newSharedACLPool()
	cfg := config.Default()
	base := acl.NewEngine(true, "", "", "", nil)

	routesV1 := []acl.DynamicRoute{
		{Action: "block", Matches: []string{"regexp:^bad1\\.example\\.com$", "regexp:^bad2\\.example\\.com$"}},
	}
	routesV2 := []acl.DynamicRoute{
		{Action: "block", Matches: []string{"regexp:^bad3\\.example\\.com$"}},
	}

	var first *acl.Engine
	for nodeID := 781; nodeID <= 800; nodeID++ {
		eng := pool.getOrBuild(nodeID, cfg.CloneForNode(nodeID), base, routesV1)
		if first == nil {
			first = eng
		} else if eng != first {
			t.Fatalf("node %d got distinct *acl.Engine despite identical dynamic routes", nodeID)
		}
	}
	pool.mu.Lock()
	countV1 := len(pool.engines)
	pool.mu.Unlock()
	if countV1 != 1 {
		t.Fatalf("expected exactly 1 compiled ACL engine in pool for 20 nodes, got %d", countV1)
	}

	// Migrate all 20 nodes to routesV2 -> old routesV1 signature must be pruned cleanly!
	var second *acl.Engine
	for nodeID := 781; nodeID <= 800; nodeID++ {
		eng := pool.getOrBuild(nodeID, cfg.CloneForNode(nodeID), base, routesV2)
		if second == nil {
			second = eng
		} else if eng != second {
			t.Fatalf("node %d did not share v2 *acl.Engine", nodeID)
		}
	}
	if second == first {
		t.Fatal("expected distinct *acl.Engine for updated routesV2")
	}
	pool.mu.Lock()
	countV2 := len(pool.engines)
	pool.mu.Unlock()
	if countV2 != 1 {
		t.Fatalf("expected old signature to be pruned leaving 1 engine in pool, got %d", countV2)
	}
}

func TestBUG9DetachedPushTrafficOnSIGTERMNoDoubleCountAndSkipAliveStatus(t *testing.T) {
	cfg := config.Default()
	cfg.NodeID = 781
	tr := stats.NewTracker(cfg)
	users, _, _, _ := tr.ReconcileUsers([]stats.SyncUserSpec{{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}})
	users[0].AddUpload(4096)
	users[0].AddDownload(8192)

	inPush := make(chan struct{})
	releasePush := make(chan struct{})
	var sawCanceledCtx atomic.Bool

	cli := &fakePanelClient{
		pushTrafficFn: func(ctx context.Context, batch []stats.TrafficDelta) error {
			close(inPush)
			<-releasePush
			if ctx.Err() != nil {
				sawCanceledCtx.Store(true)
				return ctx.Err()
			}
			return nil
		},
	}

	w := &nodeWorker{
		nodeID:               781,
		cfg:                  cfg,
		client:               cli,
		tracker:              tr,
		pushTrafficTimeout:   2 * time.Second,
		shutdownFlushTimeout: 2 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.pushToPanel(ctx)
	}()

	// Wait until PushTraffic is in flight, then simulate SIGTERM (cancel ctx)!
	<-inPush
	cancel()
	time.Sleep(25 * time.Millisecond)
	close(releasePush)
	<-done

	if sawCanceledCtx.Load() {
		t.Fatal("PushTraffic context was canceled by SIGTERM mid-flight (risking rollback & double-counting)")
	}
	if cli.pushAliveCalls.Load() != 0 {
		t.Fatalf("PushAlive should be skipped when shutting down, got %d calls", cli.pushAliveCalls.Load())
	}
	if cli.pushStatusCalls.Load() != 0 {
		t.Fatalf("PushStatus should be skipped when shutting down, got %d calls", cli.pushStatusCalls.Load())
	}

	// Now run shutdown(): because in-flight PushTraffic succeeded without rollback,
	// shutdown() must NOT push the same 4096/8192 bytes a second time!
	w.shutdown()
	if cli.pushTrafficCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 PushTraffic total (no duplicate shutdown flush), got %d", cli.pushTrafficCalls.Load())
	}
	cli.mu.Lock()
	up, down := cli.pushedUp, cli.pushedDown
	cli.mu.Unlock()
	if up != 4096 || down != 8192 {
		t.Fatalf("unexpected total pushed traffic: up=%d down=%d (want 4096/8192)", up, down)
	}
}

func TestBUG10EffectiveGCPercentHonorsExplicitConfig(t *testing.T) {
	// 1. Default (not explicitly set) + v2ray_reduce_memory=true -> 75%
	cfg1 := config.Default()
	cfg1.ApplyKV("v2ray_reduce_memory", "true")
	if got := effectiveGCPercent(cfg1); got != 75 {
		t.Fatalf("expected 75%% when v2ray_reduce_memory=true and gc_percent unset, got %d%%", got)
	}

	// 2. Explicit gc_percent=100 + v2ray_reduce_memory=true -> must stay 100%!
	cfg2 := config.Default()
	cfg2.ApplyKV("v2ray_reduce_memory", "true")
	cfg2.ApplyKV("gc_percent", "100")
	if got := effectiveGCPercent(cfg2); got != 100 {
		t.Fatalf("explicit gc_percent=100 was silently overridden to %d%%", got)
	}

	// 3. Explicit gc_percent=50 -> 50%
	cfg3 := config.Default()
	cfg3.ApplyKV("v2ray_reduce_memory", "true")
	cfg3.ApplyKV("gc_percent", "50")
	if got := effectiveGCPercent(cfg3); got != 50 {
		t.Fatalf("expected 50%%, got %d%%", got)
	}
}

func TestBUG11StartupBindRetryDoesNotRepollPanelEveryRetry(t *testing.T) {
	// Occupy a port so initial Start() fails with EADDRINUSE
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	occupiedPort := blocker.Addr().(*net.TCPAddr).Port

	cfg := config.Default()
	cfg.NodeID = 781
	cfg.ForceCloseSSL = true
	cfg.CheckInterval = 120
	cfg.SubmitInterval = 120

	cli := &fakePanelClient{
		spec: &panel.NodeSpec{
			Protocol:   "vless",
			ListenIP:   "127.0.0.1",
			ServerPort: occupiedPort,
			Network:    "tcp",
		},
		users: []stats.SyncUserSpec{{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}},
	}

	w := &nodeWorker{
		nodeID:             781,
		cfg:                cfg,
		client:             cli,
		tracker:            stats.NewTracker(cfg),
		dnsRes:             dns.NewResolver("", "", nil, "ipv4_only"),
		baseACL:            acl.NewEngine(false, "", "", "", nil),
		aclPool:            newSharedACLPool(),
		startRetryInterval: 35 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sem := make(chan struct{}, 2)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		w.runLoop(ctx, sem)
	}()

	// Let 4 local Start() retries happen (~160ms) while port is occupied.
	time.Sleep(180 * time.Millisecond)

	// Panel must have been polled ONLY ONCE (initial sync), NOT 4-5 times!
	if got := cli.fetchUsersCalls.Load(); got != 1 {
		_ = blocker.Close()
		cancel()
		<-loopDone
		t.Fatalf("startup bind retry re-polled panel FetchUsers %d times (want 1)", got)
	}
	if got := cli.fetchConfigCalls.Load(); got != 1 {
		_ = blocker.Close()
		cancel()
		<-loopDone
		t.Fatalf("startup bind retry re-polled panel FetchNodeConfig %d times (want 1)", got)
	}

	// Release the occupied port -> pendingServer.Start() must bind cleanly on next retry!
	_ = blocker.Close()

	bound := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c2, derr2 := net.DialTimeout("tcp", blocker.Addr().String(), 80*time.Millisecond); derr2 == nil {
			_ = c2.Close()
			bound = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	<-loopDone

	if !bound {
		t.Fatal("pendingServer.Start() never bound after occupied port was released")
	}
	if got := cli.fetchUsersCalls.Load(); got != 1 {
		t.Fatalf("expected 1 total FetchUsers call across bind recovery, got %d", got)
	}
}

func TestRuntimeConfigChangeBindFailureRetriesPendingServerFast(t *testing.T) {
	// Allocate two distinct ports: portA for initial bind, portB occupied during runtime switch.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	portA := lnA.Addr().(*net.TCPAddr).Port
	_ = lnA.Close()

	blockerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	portB := blockerB.Addr().(*net.TCPAddr).Port

	cfg := config.Default()
	cfg.NodeID = 782
	cfg.ForceCloseSSL = true
	cfg.CheckInterval = 120
	cfg.SubmitInterval = 120

	cli := &fakePanelClient{
		spec: &panel.NodeSpec{
			Protocol:       "vless",
			ListenIP:       "127.0.0.1",
			ServerPort:     portA,
			Network:        "tcp",
			ConfigChecksum: "v1",
		},
		users: []stats.SyncUserSpec{{ID: 1, UUIDOrPass: "b831381d-6324-4d53-ad4f-8cda48b30811"}},
	}

	w := &nodeWorker{
		nodeID:               782,
		cfg:                  cfg,
		client:               cli,
		tracker:              stats.NewTracker(cfg),
		dnsRes:               dns.NewResolver("", "", nil, "ipv4_only"),
		baseACL:              acl.NewEngine(false, "", "", "", nil),
		aclPool:              newSharedACLPool(),
		startRetryInterval:   35 * time.Millisecond,
		pullIntervalOverride: 450 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sem := make(chan struct{}, 2)

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		w.runLoop(ctx, sem)
	}()

	// Wait for portA to start accepting connections.
	addrA := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA}).String()
	readyA := false
	for dl := time.Now().Add(2 * time.Second); time.Now().Before(dl); {
		if c, derr := net.DialTimeout("tcp", addrA, 80*time.Millisecond); derr == nil {
			_ = c.Close()
			readyA = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !readyA {
		_ = blockerB.Close()
		cancel()
		<-loopDone
		t.Fatal("initial listener on portA never became ready")
	}

	// Switch panel spec to occupied portB -> runtime pull closes portA and fails to bind portB!
	cli.mu.Lock()
	cli.spec = &panel.NodeSpec{
		Protocol:       "vless",
		ListenIP:       "127.0.0.1",
		ServerPort:     portB,
		Network:        "tcp",
		ConfigChecksum: "v2",
	}
	cli.mu.Unlock()

	// Wait until runtime pull has attempted portB (portA is closed and fetchConfigCalls >= 2).
	for dl := time.Now().Add(2 * time.Second); time.Now().Before(dl); {
		if cli.fetchConfigCalls.Load() >= 2 {
			if c, derr := net.DialTimeout("tcp", addrA, 40*time.Millisecond); derr != nil {
				break
			} else {
				_ = c.Close()
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Now release portB and verify steady-state retryTimer binds portB quickly WITHOUT waiting for next pullTicker!
	pullsBeforeRelease := cli.fetchConfigCalls.Load()
	_ = blockerB.Close()
	addrB := blockerB.Addr().String()
	boundB := false
	for dl := time.Now().Add(350 * time.Millisecond); time.Now().Before(dl); {
		if c, derr := net.DialTimeout("tcp", addrB, 80*time.Millisecond); derr == nil {
			_ = c.Close()
			boundB = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	pullsAfterBind := cli.fetchConfigCalls.Load()
	cancel()
	<-loopDone
	if !boundB {
		t.Fatal("steady-state pendingServer retry failed to bind portB quickly via retryTimer")
	}
	if pullsAfterBind != pullsBeforeRelease {
		t.Fatalf("expected steady-state retryTimer to recover without re-polling panel: before=%d after=%d", pullsBeforeRelease, pullsAfterBind)
	}
}

func TestAdaptiveShutdownFlushBudget(t *testing.T) {
	w := &nodeWorker{}
	// 1. Fresh shutdown (no elapsed push time) -> full 20s budget.
	if got := w.flushTimeout(); got != defaultShutdownFlushTimeout {
		t.Fatalf("expected %v default flush timeout, got %v", defaultShutdownFlushTimeout, got)
	}

	// 2. Shutdown after 12s consumed by in-flight periodic push -> trimmed to ~12s (< 30s total).
	w.shutdownAt.Store(time.Now().Add(-12 * time.Second).UnixNano())
	gotMid := w.flushTimeout()
	if gotMid > 12500*time.Millisecond || gotMid < 11*time.Second {
		t.Fatalf("expected ~12s remaining flush budget after 12s push, got %v", gotMid)
	}

	// 3. Shutdown after >=22s elapsed -> floored at minShutdownFlushTimeout (4s).
	w.shutdownAt.Store(time.Now().Add(-23 * time.Second).UnixNano())
	if gotMin := w.flushTimeout(); gotMin != minShutdownFlushTimeout {
		t.Fatalf("expected floor %v when budget exhausted, got %v", minShutdownFlushTimeout, gotMin)
	}
}
