package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
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

// nodeWorker manages one `node_id` inside a single or multi-node Agent (`node_id=781,782,...`).
// All workers in the same process share one Go heap, one DNS resolver + cache, one HTTP/2 client pool,
// and a shared base `routes.toml` ACL engine when panel-pushed dynamic routes are absent.
type nodeWorker struct {
	nodeID  int
	cfg     *config.Config
	client  panel.Client
	tracker *stats.Tracker
	dnsRes  *dns.Resolver
	baseACL *acl.Engine

	curSpec   *panel.NodeSpec
	curServer *protocol.Server
	curUsers  []*stats.UserEntry
}

// Agent orchestrates panel synchronization, RCU hot-reload of users & ACLs,
// atomic traffic push, multi-node aggregation, and Go runtime memory/GC bounds.
type Agent struct {
	cfg     *config.Config
	dnsRes  *dns.Resolver
	baseACL *acl.Engine
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
		})
	}

	return &Agent{
		cfg:     cfg,
		dnsRes:  dnsRes,
		baseACL: baseACL,
		workers: workers,
	}, nil
}

func (a *Agent) applyRuntimeTuning() {
	gcPct := a.cfg.GCPercent
	if a.cfg.V2rayReduceMemory && gcPct >= 100 {
		gcPct = 75
	}
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
	logger.Infof("Starting %s | panel=%s nodes=%s(%d) server_type=%s gc=%d%% mem_limit=%dMiB",
		version.Summary(), panelName, a.cfg.FormatNodeIDs(), len(a.workers), a.cfg.NormalizedServerType(), gcPct, a.cfg.MemLimitMB)
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

	scavengeTicker := time.NewTicker(2 * time.Minute)
	defer scavengeTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-scavengeTicker.C:
			// Gently return unused heap spans to Linux kernel (`MADV_DONTNEED`)
			debug.FreeOSMemory()
		}
	}
}

func (w *nodeWorker) runLoop(ctx context.Context, bootstrapSem chan struct{}) {
	for {
		bootstrapSem <- struct{}{}
		err := w.syncFromPanel(ctx, true)
		<-bootstrapSem
		if err == nil {
			break
		}
		logger.Errorf("[node %d] Initial panel sync failed (retrying in 5s): %v", w.nodeID, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
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
	if len(routes) == 0 && w.baseACL != nil {
		return w.baseACL
	}
	eng := acl.NewEngine(w.cfg.ForbiddenBitTorrent, w.cfg.WhiteListPath, w.cfg.BlockListPath, w.cfg.RoutesPath, routes)
	eng.SetPortAndPrivatePolicy(w.cfg.ForbiddenPorts, w.cfg.BanPrivateIP)
	return eng
}

func (w *nodeWorker) syncFromPanel(ctx context.Context, first bool) error {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var configChanged bool
	newSpec, err := w.client.FetchNodeConfig(reqCtx)
	if err != nil {
		if !errors.Is(err, panel.ErrNotModified) {
			return err
		}
	} else if newSpec != nil {
		if w.curSpec == nil || listenerNeedsRestart(w.curSpec, newSpec) {
			configChanged = true
		} else if w.curSpec.ConfigChecksum != newSpec.ConfigChecksum && w.curServer != nil {
			w.curServer.UpdateACL(w.buildACL(newSpec.Routes))
			logger.Infof("[node %d] Hot-reloaded ACL & panel routes (%d rules)", w.nodeID, len(newSpec.Routes))
		}
		w.curSpec = newSpec
	}

	if w.curSpec == nil {
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

	if aliveMap, aerr := w.client.FetchAliveList(reqCtx); aerr == nil && aliveMap != nil {
		w.tracker.ApplyRemoteAliveList(aliveMap)
	}

	ssKeySize := 0
	if w.curSpec.Protocol == "shadowsocks" {
		if w.curSpec.Cipher == "aes-128-gcm" || w.curSpec.Cipher == "2022-blake3-aes-128-gcm" {
			ssKeySize = 16
		} else {
			ssKeySize = 32
		}
	}

	if configChanged || w.curServer == nil {
		idx := protocol.BuildUserIndexForProtocol(w.curSpec.Protocol, w.curUsers, ssKeySize)
		aclEng := w.buildACL(w.curSpec.Routes)
		srv, err := protocol.NewServer(w.cfg, w.curSpec, w.tracker, idx, aclEng, w.dnsRes)
		if err != nil {
			return err
		}
		if w.curServer != nil {
			logger.Infof("[node %d] Listener config changed; restarting inbound gracefully...", w.nodeID)
			w.curServer.Close()
		}
		if err := srv.Start(); err != nil {
			return err
		}
		w.curServer = srv
		logger.Infof("[node %d] Loaded %d active users (goroutines=%d)", w.nodeID, len(w.curUsers), runtime.NumGoroutine())
		return nil
	}

	if usersModified && w.curServer != nil {
		idx := protocol.BuildUserIndexForProtocol(w.curSpec.Protocol, w.curUsers, w.curServer.SSKeySize())
		w.curServer.UpdateUsers(idx)
		logger.Infof("[node %d] Users synced (total=%d, +%d ~%d -%d)", w.nodeID, len(w.curUsers), added, updated, removed)
	}
	return nil
}

func (w *nodeWorker) pushToPanel(ctx context.Context) {
	pushCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	batch := w.tracker.HarvestTraffic(1024)
	if len(batch) > 0 {
		if err := w.client.PushTraffic(pushCtx, batch); err != nil {
			logger.Warnf("[node %d] PushTraffic (%d users) failed, rolling back counters: %v", w.nodeID, len(batch), err)
			w.tracker.RollbackTraffic(batch)
		} else {
			logger.Debugf("[node %d] Pushed traffic for %d active users", w.nodeID, len(batch))
		}
	}

	alive := w.tracker.SnapshotAliveMap()
	if len(alive) > 0 {
		if err := w.client.PushAlive(pushCtx, alive); err != nil {
			logger.Debugf("[node %d] PushAlive warning: %v", w.nodeID, err)
		}
	}

	sysSt := panel.CollectSystemStatus()
	if err := w.client.PushStatus(pushCtx, sysSt); err != nil {
		logger.Debugf("[node %d] PushStatus warning: %v", w.nodeID, err)
	}
}

func (w *nodeWorker) shutdown() {
	if w.curServer != nil {
		w.curServer.Close()
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	batch := w.tracker.HarvestTraffic(0)
	if len(batch) > 0 {
		if err := w.client.PushTraffic(flushCtx, batch); err != nil {
			logger.Warnf("[node %d] Final traffic flush failed: %v", w.nodeID, err)
		}
	}
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
		oldSpec.ServerName != newSpec.ServerName
}
