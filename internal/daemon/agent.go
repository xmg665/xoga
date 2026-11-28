package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/dns"
	"github.com/xmg665/xoga/internal/logger"
	"github.com/xmg665/xoga/internal/panel"
	"github.com/xmg665/xoga/internal/protocol"
	"github.com/xmg665/xoga/internal/stats"
	"github.com/xmg665/xoga/internal/version"
)

const (
	defaultPushTrafficTimeout   = 12 * time.Second
	defaultShutdownFlushTimeout = 12 * time.Second
	defaultStartRetryInterval   = 5 * time.Second
)

type serverStartError struct {
	err error
}

func (e *serverStartError) Error() string { return e.err.Error() }
func (e *serverStartError) Unwrap() error { return e.err }

// sharedACLPool shares compiled *acl.Engine instances across all multi-node workers whose
// panel-pushed dynamic routes have an identical signature, avoiding 20x regex compilation
// and 20x concurrent routes.toml hot-reload storms while pruning unreferenced snapshots.
type sharedACLPool struct {
	mu      sync.Mutex
	engines map[string]*acl.Engine
	byNode  map[int]string
}

func newSharedACLPool() *sharedACLPool {
	return &sharedACLPool{
		engines: make(map[string]*acl.Engine),
		byNode:  make(map[int]string),
	}
}

func dynamicRoutesSignature(routes []acl.DynamicRoute) string {
	h := sha256.New()
	var lenBuf [8]byte
	writeStr := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(s))
	}
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(routes)))
	_, _ = h.Write(lenBuf[:])
	for _, r := range routes {
		writeStr(r.Action)
		writeStr(r.ActionValue)
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(r.Matches)))
		_, _ = h.Write(lenBuf[:])
		for _, m := range r.Matches {
			writeStr(m)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (p *sharedACLPool) pruneLocked(sig string) {
	if sig == "" {
		return
	}
	for _, used := range p.byNode {
		if used == sig {
			return
		}
	}
	delete(p.engines, sig)
}

func (p *sharedACLPool) getOrBuild(nodeID int, cfg *config.Config, base *acl.Engine, routes []acl.DynamicRoute) *acl.Engine {
	if len(routes) == 0 && base != nil {
		if p != nil {
			p.mu.Lock()
			if prev, ok := p.byNode[nodeID]; ok {
				delete(p.byNode, nodeID)
				p.pruneLocked(prev)
			}
			p.mu.Unlock()
		}
		return base
	}
	if p == nil {
		eng := acl.NewEngine(cfg.ForbiddenBitTorrent, cfg.WhiteListPath, cfg.BlockListPath, cfg.RoutesPath, routes)
		eng.SetPortAndPrivatePolicy(cfg.ForbiddenPorts, cfg.BanPrivateIP)
		return eng
	}
	sig := dynamicRoutesSignature(routes)
	p.mu.Lock()
	defer p.mu.Unlock()
	prev := p.byNode[nodeID]
	eng := p.engines[sig]
	if eng == nil {
		eng = acl.NewEngine(cfg.ForbiddenBitTorrent, cfg.WhiteListPath, cfg.BlockListPath, cfg.RoutesPath, routes)
		eng.SetPortAndPrivatePolicy(cfg.ForbiddenPorts, cfg.BanPrivateIP)
		p.engines[sig] = eng
	}
	p.byNode[nodeID] = sig
	if prev != "" && prev != sig {
		p.pruneLocked(prev)
	}
	return eng
}

// nodeWorker manages one `node_id` inside a single or multi-node Agent (`node_id=781,782,...`).
// All workers in the same process share one Go heap, one DNS resolver + cache, one HTTP/2 client pool,
// and shared compiled ACL engines across identical dynamic-route signatures.
type nodeWorker struct {
	nodeID  int
	cfg     *config.Config
	client  panel.Client
	tracker *stats.Tracker
	dnsRes  *dns.Resolver
	baseACL *acl.Engine
	aclPool *sharedACLPool

	curSpec       *panel.NodeSpec
	curServer     *protocol.Server
	pendingServer *protocol.Server
	curUsers      []*stats.UserEntry

	// Optional overrides for fast deterministic unit tests (0 = production defaults).
	pushTrafficTimeout   time.Duration
	shutdownFlushTimeout time.Duration
	startRetryInterval   time.Duration
}

func (w *nodeWorker) trafficTimeout() time.Duration {
	if w.pushTrafficTimeout > 0 {
		return w.pushTrafficTimeout
	}
	return defaultPushTrafficTimeout
}

func (w *nodeWorker) flushTimeout() time.Duration {
	if w.shutdownFlushTimeout > 0 {
		return w.shutdownFlushTimeout
	}
	return defaultShutdownFlushTimeout
}

func (w *nodeWorker) retryInterval() time.Duration {
	if w.startRetryInterval > 0 {
		return w.startRetryInterval
	}
	return defaultStartRetryInterval
}

// Agent orchestrates panel synchronization, RCU hot-reload of users & ACLs,
// atomic traffic push, multi-node aggregation, and Go runtime memory/GC bounds.
type Agent struct {
	cfg     *config.Config
	dnsRes  *dns.Resolver
	baseACL *acl.Engine
	aclPool *sharedACLPool
	workers []*nodeWorker
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	nodeIDs := cfg.EffectiveNodeIDs()

	maxPerHost := 4
	if len(nodeIDs) > 2 {
		maxPerHost = min(len(nodeIDs), 16)
	}
	httpCli := panel.NewKeepAliveHTTPClient(maxPerHost)

	dnsRes := dns.NewResolver(cfg.DNSConfigPath, cfg.DNSConfigURL, cfg.DefaultDNS, cfg.DNSStrategy)
	dnsRes.SetCacheMinutes(cfg.DNSCacheTime)

	baseACL := acl.NewEngine(cfg.ForbiddenBitTorrent, cfg.WhiteListPath, cfg.BlockListPath, cfg.RoutesPath, nil)
	baseACL.SetPortAndPrivatePolicy(cfg.ForbiddenPorts, cfg.BanPrivateIP)
	aclPool := newSharedACLPool()

	workers := make([]*nodeWorker, 0, len(nodeIDs))
	for _, nid := range nodeIDs {
		nodeCfg := cfg.CloneForNode(nid)
		cli, err := panel.NewClientWithHTTP(nodeCfg, httpCli)
		if err != nil {
			return nil, err
		}
		workers = append(workers, &nodeWorker{
			nodeID:  nid,
			cfg:     nodeCfg,
			client:  cli,
			tracker: stats.NewTracker(nodeCfg),
			dnsRes:  dnsRes,
			baseACL: baseACL,
			aclPool: aclPool,
		})
	}

	return &Agent{
		cfg:     cfg,
		dnsRes:  dnsRes,
		baseACL: baseACL,
		aclPool: aclPool,
		workers: workers,
	}, nil
}

func effectiveGCPercent(cfg *config.Config) int {
	gcPct := cfg.GCPercent
	if cfg.V2rayReduceMemory && !cfg.GCPercentSet && gcPct == 100 {
		gcPct = 75
	}
	return gcPct
}

func (a *Agent) applyRuntimeTuning() {
	gcPct := effectiveGCPercent(a.cfg)
	if gcPct > 0 {
		debug.SetGCPercent(gcPct)
	}
	if a.cfg.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(a.cfg.MemLimitMB) * 1024 * 1024)
	}
	panelName := a.cfg.Type
	if len(a.workers) > 0 {
		panelName = a.workers[0].client.Name()
	}
	logger.Infof("Starting %s | panel=%s nodes=%s(%d) server_type=%s device_limit=%v gc=%d%% mem_limit=%dMiB",
		version.Summary(), panelName, a.cfg.FormatNodeIDs(), len(a.workers), a.cfg.NormalizedServerType(), a.cfg.DeviceLimitEnable, gcPct, a.cfg.MemLimitMB)
}

func (a *Agent) Run(ctx context.Context) error {
	a.applyRuntimeTuning()

	// Parallel bounded bootstrap across all configured node_ids (up to 6 concurrent syncs)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, w := range a.workers {
		wg.Add(1)
		go func(idx int, nw *nodeWorker) {
			defer wg.Done()
			// Stagger multi-node loops slightly so 18+ nodes never burst panel DB at the same instant
			if idx > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(idx*120) * time.Millisecond):
				}
			}
			nw.runLoop(ctx, sem)
		}(i, w)
	}

	<-ctx.Done()
	wg.Wait()
	return nil
}

func (w *nodeWorker) runLoop(ctx context.Context, bootstrapSem chan struct{}) {
	retryDur := w.retryInterval()
	panelRefreshEvery := max(w.cfg.CheckInterval/5, 12)
	localStartRetries := 0

	for {
		if ctx.Err() != nil {
			w.pendingServer = nil
			return
		}
		if w.pendingServer != nil && localStartRetries < panelRefreshEvery {
			// Local bind/start retry: avoid re-polling full panel user JSON every 5s while
			// waiting for a local port conflict to clear.
			err := w.pendingServer.Start()
			if err == nil {
				w.curServer = w.pendingServer
				w.pendingServer = nil
				logger.Infof("[node %d] Loaded %d active users (goroutines=%d)", w.nodeID, len(w.curUsers), runtime.NumGoroutine())
				break
			}
			localStartRetries++
			logger.Errorf("[node %d] Inbound start failed (retrying in %s): %v", w.nodeID, retryDur, err)
		} else {
			localStartRetries = 0
			bootstrapSem <- struct{}{}
			err := w.syncFromPanel(ctx, true)
			<-bootstrapSem
			if err == nil {
				break
			}
			var startErr *serverStartError
			if errors.As(err, &startErr) {
				localStartRetries = 1
				logger.Errorf("[node %d] Inbound start failed (retrying in %s): %v", w.nodeID, retryDur, startErr.err)
			} else {
				logger.Errorf("[node %d] Initial panel sync failed (retrying in %s): %v", w.nodeID, retryDur, err)
			}
		}
		select {
		case <-ctx.Done():
			w.pendingServer = nil
			return
		case <-time.After(retryDur):
		}
	}

	pullSec := w.cfg.CheckInterval
	if w.curSpec != nil && w.curSpec.PullInterval >= 10 && w.cfg.CheckInterval == 60 {
		pullSec = w.curSpec.PullInterval
	}
	pushSec := w.cfg.SubmitInterval
	if w.curSpec != nil && w.curSpec.PushInterval >= 10 && w.cfg.SubmitInterval == 60 {
		pushSec = w.curSpec.PushInterval
	}

	pullTicker := time.NewTicker(time.Duration(pullSec) * time.Second)
	pushTicker := time.NewTicker(time.Duration(pushSec) * time.Second)
	var dyCh <-chan time.Time
	var dyTicker *time.Ticker
	if w.cfg.DyLimitEnable {
		dyTicker = time.NewTicker(time.Second)
		dyCh = dyTicker.C
	}

	defer func() {
		pullTicker.Stop()
		pushTicker.Stop()
		if dyTicker != nil {
			dyTicker.Stop()
		}
		w.shutdown()
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-dyCh:
			w.tracker.TickDynamicSpeedLimit()
		case <-pullTicker.C:
			if err := w.syncFromPanel(ctx, false); err != nil {
				logger.Warnf("[node %d] Panel pull failed: %v", w.nodeID, err)
			}
		case <-pushTicker.C:
			w.pushToPanel(ctx)
		}
	}
}

func (w *nodeWorker) buildACL(routes []acl.DynamicRoute) *acl.Engine {
	return w.aclPool.getOrBuild(w.nodeID, w.cfg, w.baseACL, routes)
}

func (w *nodeWorker) syncFromPanel(ctx context.Context, first bool) error {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var configChanged bool
	var aclOnlyChanged bool
	effectiveSpec := w.curSpec

	newSpec, err := w.client.FetchNodeConfig(reqCtx)
	if err != nil {
		if !errors.Is(err, panel.ErrNotModified) {
			return err
		}
		// On first sync, ErrNotModified means the ETag was latched but w.curSpec is nil.
		// Clear the ETag so the next attempt re-fetches.
		if first && w.curSpec == nil {
			w.client.ClearNodeConfigETag()
			return fmt.Errorf("empty node config (ETag cleared for retry)")
		}
	} else if newSpec != nil {
		if w.curSpec == nil || listenerNeedsRestart(w.curSpec, newSpec) {
			configChanged = true
		} else if w.curSpec.ConfigChecksum != newSpec.ConfigChecksum {
			aclOnlyChanged = true
		}
		effectiveSpec = newSpec
	}

	if effectiveSpec == nil {
		return fmt.Errorf("empty node config")
	}

	userSpecs, err := w.client.FetchUsers(reqCtx)
	usersModified := false
	var added, updated, removed int
	if err != nil {
		if !errors.Is(err, panel.ErrNotModified) {
			if first {
				return err
			}
			logger.Warnf("[node %d] FetchUsers error (keeping %d cached users): %v", w.nodeID, len(w.curUsers), err)
		}
	} else {
		w.curUsers, added, updated, removed = w.tracker.ReconcileUsers(userSpecs)
		usersModified = (added+updated+removed > 0) || first
	}

	if aliveList, aerr := w.client.FetchAliveList(reqCtx); aerr == nil && aliveList != nil {
		if aliveList.Counts != nil {
			w.tracker.ApplyRemoteAliveCounts(aliveList.Counts)
		} else {
			w.tracker.ApplyRemoteAliveList(aliveList.IPs)
		}
	}

	if configChanged || w.curServer == nil {
		idx := protocol.BuildUserIndexForCipher(effectiveSpec.Protocol, effectiveSpec.Cipher, w.curUsers)
		aclEng := w.buildACL(effectiveSpec.Routes)
		srv, err := protocol.NewServer(w.cfg, effectiveSpec, w.tracker, idx, aclEng, w.dnsRes)
		if err != nil {
			// Keep old w.curServer & w.curSpec untouched if constructing new server failed!
			// Clear ETags so next poll re-fetches config instead of getting 304.
			w.client.ClearNodeConfigETag()
			return err
		}
		w.curSpec = effectiveSpec
		if w.curServer != nil {
			logger.Infof("[node %d] Listener config changed; restarting inbound gracefully...", w.nodeID)
			w.curServer.Close()
			// Clear curServer immediately so if srv.Start() fails (e.g. transient port/cert issue),
			// subsequent polling ticks see w.curServer == nil and retry Start() even on HTTP 304!
			w.curServer = nil
		}
		if err := srv.Start(); err != nil {
			w.pendingServer = srv
			return &serverStartError{err: err}
		}
		w.pendingServer = nil
		w.curServer = srv
		logger.Infof("[node %d] Loaded %d active users (goroutines=%d)", w.nodeID, len(w.curUsers), runtime.NumGoroutine())
		return nil
	}

	if aclOnlyChanged && w.curServer != nil {
		w.curSpec = effectiveSpec
		w.curServer.UpdateACL(w.buildACL(effectiveSpec.Routes))
		logger.Infof("[node %d] Hot-reloaded ACL & panel routes (%d rules)", w.nodeID, len(effectiveSpec.Routes))
	}

	if usersModified && w.curServer != nil {
		idx := protocol.BuildUserIndexForCipher(w.curSpec.Protocol, w.curSpec.Cipher, w.curUsers)
		w.curServer.UpdateUsers(idx)
		logger.Infof("[node %d] Users synced (total=%d, +%d ~%d -%d)", w.nodeID, len(w.curUsers), added, updated, removed)
	}
	return nil
}

func (w *nodeWorker) pushToPanel(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	batch := w.tracker.HarvestTraffic(1024)
	if len(batch) > 0 {
		// Use a detached bounded context for already-started PushTraffic so SIGTERM mid-push
		// never cancels an in-flight traffic report (which would risk double counting on
		// shutdown flush) while staying well within systemd's 30s TimeoutStopUSec.
		trafficCtx, trafficCancel := context.WithTimeout(context.Background(), w.trafficTimeout())
		err := w.client.PushTraffic(trafficCtx, batch)
		trafficCancel()
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, context.DeadlineExceeded) {
				logger.Warnf("[node %d] PushTraffic (%d users) timed out during shutdown; skipping rollback to avoid double counting: %v", w.nodeID, len(batch), err)
			} else {
				logger.Warnf("[node %d] PushTraffic (%d users) failed, rolling back counters: %v", w.nodeID, len(batch), err)
				w.tracker.RollbackTraffic(batch)
			}
		} else {
			logger.Debugf("[node %d] Pushed traffic for %d active users", w.nodeID, len(batch))
		}
	}

	// Skip non-essential alive/status pushes when shutting down.
	if ctx.Err() != nil {
		return
	}

	pushCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	alive := w.tracker.SnapshotAliveMap()
	if len(alive) > 0 {
		if err := w.client.PushAlive(pushCtx, alive); err != nil {
			logger.Debugf("[node %d] PushAlive warning: %v", w.nodeID, err)
		}
	}

	if ctx.Err() != nil {
		return
	}

	sysSt := panel.CollectSystemStatus()
	if err := w.client.PushStatus(pushCtx, sysSt); err != nil {
		logger.Debugf("[node %d] PushStatus warning: %v", w.nodeID, err)
	}
}

func (w *nodeWorker) shutdown() {
	w.pendingServer = nil
	if w.curServer != nil {
		w.curServer.Close()
		w.curServer = nil
	}
	// systemd stops us after 30s; cap final flush to 12s (paired with 12s detached periodic
	// PushTraffic so worst-case total shutdown stays well under 30s). A single attempt avoids
	// double counting if the panel applied a request whose reply was lost.
	batch := w.tracker.HarvestTraffic(0)
	if len(batch) == 0 {
		return
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), w.flushTimeout())
	defer cancel()
	if err := w.client.PushTraffic(flushCtx, batch); err != nil {
		logger.Warnf("[node %d] Final traffic flush failed, %d users' traffic lost: %v", w.nodeID, len(batch), err)
		return
	}
	logger.Infof("[node %d] Final traffic flush pushed %d users", w.nodeID, len(batch))
}

func listenerNeedsRestart(oldSpec, newSpec *panel.NodeSpec) bool {
	return oldSpec.Protocol != newSpec.Protocol ||
		oldSpec.ListenIP != newSpec.ListenIP ||
		oldSpec.ServerPort != newSpec.ServerPort ||
		oldSpec.Network != newSpec.Network ||
		oldSpec.WSPath != newSpec.WSPath ||
		oldSpec.Cipher != newSpec.Cipher ||
		oldSpec.ServerKey != newSpec.ServerKey ||
		oldSpec.TLSMode != newSpec.TLSMode ||
		oldSpec.ServerName != newSpec.ServerName ||
		oldSpec.Flow != newSpec.Flow ||
		oldSpec.RealityDest != newSpec.RealityDest ||
		oldSpec.RealityPrivateKey != newSpec.RealityPrivateKey ||
		!slices.Equal(oldSpec.RealityShortIDs, newSpec.RealityShortIDs) ||
		!slices.Equal(oldSpec.RealityServerNames, newSpec.RealityServerNames) ||
		oldSpec.Hy2Obfs != newSpec.Hy2Obfs ||
		oldSpec.Hy2ObfsPassword != newSpec.Hy2ObfsPassword ||
		oldSpec.Hy2DownMbps != newSpec.Hy2DownMbps ||
		oldSpec.Hy2IgnoreClientBW != newSpec.Hy2IgnoreClientBW ||
		oldSpec.AnyTLSPaddingScheme != newSpec.AnyTLSPaddingScheme
}
