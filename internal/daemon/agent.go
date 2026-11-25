package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
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

// Agent orchestrates panel synchronization, RCU hot-reload of users & ACLs,
// atomic traffic push, and Go runtime memory/GC bounds.
type Agent struct {
	cfg     *config.Config
	client  panel.Client
	tracker *stats.Tracker
	dnsRes  *dns.Resolver

	curSpec   *panel.NodeSpec
	curServer *protocol.Server
	curUsers  []*stats.UserEntry
}

func NewAgent(cfg *config.Config) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cli, err := panel.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Agent{
		cfg:     cfg,
		client:  cli,
		tracker: stats.NewTracker(cfg),
		dnsRes:  dns.NewResolver(cfg.DNSConfigPath, cfg.DNSConfigURL, cfg.DefaultDNS, cfg.DNSStrategy),
	}, nil
}

func (a *Agent) applyRuntimeTuning() {
	if a.cfg.GCPercent > 0 {
		debug.SetGCPercent(a.cfg.GCPercent)
	}
	if a.cfg.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(a.cfg.MemLimitMB) * 1024 * 1024)
	}
	logger.Infof("Starting %s | panel=%s node_id=%d server_type=%s gc=%d%% mem_limit=%dMiB",
		version.Summary(), a.client.Name(), a.cfg.NodeID, a.cfg.NormalizedServerType(), a.cfg.GCPercent, a.cfg.MemLimitMB)
}

func (a *Agent) Run(ctx context.Context) error {
	a.applyRuntimeTuning()

	// Initial bootstrap sync (retry until panel responds or context is cancelled)
	for {
		if err := a.syncFromPanel(ctx, true); err != nil {
			logger.Errorf("Initial panel sync failed (retrying in 5s): %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
				continue
			}
		}
		break
	}

	pullSec := a.cfg.CheckInterval
	if a.curSpec != nil && a.curSpec.PullInterval >= 10 && a.cfg.CheckInterval == 60 {
		pullSec = a.curSpec.PullInterval
	}
	pushSec := a.cfg.SubmitInterval
	if a.curSpec != nil && a.curSpec.PushInterval >= 10 && a.cfg.SubmitInterval == 60 {
		pushSec = a.curSpec.PushInterval
	}

	pullTicker := time.NewTicker(time.Duration(pullSec) * time.Second)
	pushTicker := time.NewTicker(time.Duration(pushSec) * time.Second)
	var dyCh <-chan time.Time
	var dyTicker *time.Ticker
	if a.cfg.DyLimitEnable {
		dyTicker = time.NewTicker(time.Second)
		dyCh = dyTicker.C
	}
	scavengeTicker := time.NewTicker(5 * time.Minute)

	defer func() {
		pullTicker.Stop()
		pushTicker.Stop()
		if dyTicker != nil {
			dyTicker.Stop()
		}
		scavengeTicker.Stop()
		a.shutdown(context.Background())
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-dyCh:
			a.tracker.TickDynamicSpeedLimit()
		case <-pullTicker.C:
			if err := a.syncFromPanel(ctx, false); err != nil {
				logger.Warnf("Panel pull failed: %v", err)
			}
		case <-pushTicker.C:
			a.pushToPanel(ctx)
		case <-scavengeTicker.C:
			// Gently return unused heap spans to Linux kernel (`MADV_DONTNEED`) during low traffic
			debug.FreeOSMemory()
		}
	}
}

func (a *Agent) syncFromPanel(ctx context.Context, first bool) error {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	var configChanged bool
	newSpec, err := a.client.FetchNodeConfig(reqCtx)
	if err != nil {
		if !errors.Is(err, panel.ErrNotModified) {
			return err
		}
	} else if newSpec != nil {
		if a.curSpec == nil || listenerNeedsRestart(a.curSpec, newSpec) {
			configChanged = true
		} else if a.curSpec.ConfigChecksum != newSpec.ConfigChecksum && a.curServer != nil {
			// Only routes or intervals changed -> hot-swap ACL without dropping connections!
			newACL := acl.NewEngine(a.cfg.ForbiddenBitTorrent, a.cfg.WhiteListPath, a.cfg.BlockListPath, a.cfg.RoutesPath, newSpec.Routes)
			newACL.SetPortAndPrivatePolicy(a.cfg.ForbiddenPorts, a.cfg.BanPrivateIP)
			a.curServer.UpdateACL(newACL)
			logger.Infof("Hot-reloaded ACL & panel routes (%d rules)", len(newSpec.Routes))
		}
		a.curSpec = newSpec
	}

	if a.curSpec == nil {
		return fmt.Errorf("empty node config")
	}

	userSpecs, err := a.client.FetchUsers(reqCtx)
	usersModified := false
	var added, updated, removed int
	if err != nil {
		if !errors.Is(err, panel.ErrNotModified) {
			if first {
				return err
			}
			logger.Warnf("FetchUsers error (keeping %d cached users): %v", len(a.curUsers), err)
		}
	} else {
		a.curUsers, added, updated, removed = a.tracker.ReconcileUsers(userSpecs)
		usersModified = (added+updated+removed > 0) || first
	}

	if aliveMap, aerr := a.client.FetchAliveList(reqCtx); aerr == nil && aliveMap != nil {
		a.tracker.ApplyRemoteAliveList(aliveMap)
	}

	ssKeySize := 0
	if a.curSpec.Protocol == "shadowsocks" {
		if a.curSpec.Cipher == "aes-128-gcm" || a.curSpec.Cipher == "2022-blake3-aes-128-gcm" {
			ssKeySize = 16
		} else {
			ssKeySize = 32
		}
	}

	if configChanged || a.curServer == nil {
		idx := protocol.BuildUserIndex(a.curUsers, ssKeySize)
		aclEng := acl.NewEngine(a.cfg.ForbiddenBitTorrent, a.cfg.WhiteListPath, a.cfg.BlockListPath, a.cfg.RoutesPath, a.curSpec.Routes)
		aclEng.SetPortAndPrivatePolicy(a.cfg.ForbiddenPorts, a.cfg.BanPrivateIP)
		srv, err := protocol.NewServer(a.cfg, a.curSpec, a.tracker, idx, aclEng, a.dnsRes)
		if err != nil {
			return err
		}
		if a.curServer != nil {
			logger.Infof("Node listener config changed; restarting inbound gracefully...")
			a.curServer.Close()
		}
		if err := srv.Start(); err != nil {
			return err
		}
		a.curServer = srv
		logger.Infof("Loaded %d active users (goroutines=%d)", len(a.curUsers), runtime.NumGoroutine())
		return nil
	}

	if usersModified && a.curServer != nil {
		idx := protocol.BuildUserIndex(a.curUsers, a.curServer.SSKeySize())
		a.curServer.UpdateUsers(idx)
		logger.Infof("Users synced (total=%d, +%d ~%d -%d)", len(a.curUsers), added, updated, removed)
	}
	return nil
}

func (a *Agent) pushToPanel(ctx context.Context) {
	pushCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// 1. Harvest & push user traffic (minimum 1 KiB threshold to avoid noise)
	batch := a.tracker.HarvestTraffic(1024)
	if len(batch) > 0 {
		if err := a.client.PushTraffic(pushCtx, batch); err != nil {
			logger.Warnf("PushTraffic (%d users) failed, rolling back counters: %v", len(batch), err)
			a.tracker.RollbackTraffic(batch)
		} else {
			logger.Debugf("Pushed traffic for %d active users", len(batch))
		}
	}

	// 2. Push active client IPs
	alive := a.tracker.SnapshotAliveMap()
	if len(alive) > 0 {
		if err := a.client.PushAlive(pushCtx, alive); err != nil {
			logger.Debugf("PushAlive warning: %v", err)
		}
	}

	// 3. Push lightweight host metrics
	sysSt := panel.CollectSystemStatus()
	if err := a.client.PushStatus(pushCtx, sysSt); err != nil {
		logger.Debugf("PushStatus warning: %v", err)
	}
}

func (a *Agent) shutdown(ctx context.Context) {
	logger.Infof("Shutting down node agent, flushing remaining traffic...")
	if a.curServer != nil {
		a.curServer.Close()
	}
	flushCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	batch := a.tracker.HarvestTraffic(0)
	if len(batch) > 0 {
		if err := a.client.PushTraffic(flushCtx, batch); err != nil {
			logger.Warnf("Final traffic flush failed: %v", err)
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
