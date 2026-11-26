package stats

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/limiter"
)

var (
	ErrUserDisabled = errors.New("user disabled")
	ErrTCPLimit     = errors.New("user tcp connection limit exceeded")
	ErrIPLimit      = errors.New("user online device/IP limit exceeded")
)

// TrafficDelta represents atomic harvested upload/download bytes for one user.
type TrafficDelta struct {
	UserID   int
	Upload   int64
	Download int64
}

// UserEntry holds hot per-user counters and auth keys.
// Hot atomic fields are isolated from cold metadata to minimize CPU cache-line false sharing.
type UserEntry struct {
	// Immutable / rarely-updated identity & cached protocol hashes
	ID             int
	UUID           string
	Passwd         string
	UUIDBytes      [16]byte
	HasUUID        bool
	TrojanHash     [56]byte // hex-encoded SHA-224 of password/UUID
	SHA256UUID     [32]byte // raw SHA-256(UUID) for AnyTLS O(1) auth
	SHA256Passwd   [32]byte // raw SHA-256(Passwd) for AnyTLS O(1) auth
	VMessCmdKey    [16]byte
	VMessAuthBlock cipher.Block
	VMessAuthReady bool

	// Cache-line padding before hot atomic traffic counters
	_ [64]byte

	upBytes   atomic.Int64
	downBytes atomic.Int64
	winBytes  atomic.Int64 // bytes accumulated during current dynamic limit tick
	activeTCP atomic.Int32
	activeMux atomic.Int32
	activeUDP atomic.Int32
	disabled  atomic.Bool   // set true immediately when account expires or exceeds traffic quota
	hasQuota  atomic.Bool   // true when real-time byte quota enforcement is active
	quotaRem  atomic.Int64  // real-time remaining bytes before instant kick when hasQuota == true
	quotaGen  atomic.Uint64 // generation counter preventing stale preempted AddUpload/AddDownload from disabling renewed users

	_ [64]byte

	// Limits & dynamic speed limit state
	baseSpeedBps    atomic.Int64
	deviceLimit     atomic.Int32
	tcpLimit        atomic.Int32
	overSpeedSec    atomic.Int32
	throttledUntil  atomic.Int64 // Unix seconds
	dyWhitelisted   atomic.Bool
	Limiter         *limiter.Bucket

	// Active connections registry for instant millisecond-level disconnect on expiry / quota exhaustion
	connsMu     sync.Mutex
	nextConnID  atomic.Uint64
	activeConns map[uint64]io.Closer

	// Per-user active client IPs (lazily allocated only when user connects -> saves ~28 MiB across multi-node idle users)
	ipMu        sync.RWMutex
	activeIPs   map[netip.Addr]int64 // lastSeen Unix seconds
	remoteIPs   map[netip.Addr]struct{}
	remoteCount atomic.Int32 // cluster-wide integer device count reported by Xboard / NewV2Board /alivelist
}

func precomputeVMessAuth(uuid [16]byte) ([16]byte, cipher.Block, bool) {
	const vmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"
	mh := md5.New()
	mh.Write(uuid[:])
	mh.Write([]byte(vmessMagic))
	var cmdKey [16]byte
	copy(cmdKey[:], mh.Sum(nil))

	innerHMAC := hmac.New(func() hash.Hash {
		return hmac.New(sha256.New, []byte("VMess AEAD KDF"))
	}, []byte("AES Auth ID Encryption"))
	innerHMAC.Write(cmdKey[:])
	authKey := innerHMAC.Sum(nil)[:16]
	blk, err := aes.NewCipher(authKey)
	if err != nil {
		return cmdKey, nil, false
	}
	return cmdKey, blk, true
}

func NewUserEntry(id int, uuidOrPass string, speedLimitBps int64, deviceLimit int, tcpLimit int, dyWhite bool) *UserEntry {
	u := &UserEntry{
		ID:      id,
		UUID:    uuidOrPass,
		Passwd:  uuidOrPass,
		Limiter: limiter.NewBucketBps(speedLimitBps),
	}
	u.baseSpeedBps.Store(speedLimitBps)
	u.deviceLimit.Store(int32(deviceLimit))
	u.tcpLimit.Store(int32(tcpLimit))
	u.dyWhitelisted.Store(dyWhite)
	u.RefreshKeys(uuidOrPass)
	return u
}

func (u *UserEntry) RefreshKeys(uuidOrPass string) {
	u.UUID = uuidOrPass
	u.Passwd = uuidOrPass
	if parsed, err := parseUUIDBytes(uuidOrPass); err == nil {
		u.UUIDBytes = parsed
		u.HasUUID = true
		u.VMessCmdKey, u.VMessAuthBlock, u.VMessAuthReady = precomputeVMessAuth(parsed)
	} else {
		u.HasUUID = false
		u.VMessAuthReady = false
		u.VMessAuthBlock = nil
	}
	sum224 := sha256.Sum224([]byte(uuidOrPass))
	hex.Encode(u.TrojanHash[:], sum224[:])
	u.SHA256UUID = sha256.Sum256([]byte(u.UUID))
	u.SHA256Passwd = u.SHA256UUID
}

func (u *UserEntry) RefreshDualKeys(uuid, passwd string) {
	if uuid == "" {
		uuid = passwd
	}
	if passwd == "" {
		passwd = uuid
	}
	u.UUID = uuid
	u.Passwd = passwd
	if parsed, err := parseUUIDBytes(uuid); err == nil {
		u.UUIDBytes = parsed
		u.HasUUID = true
		u.VMessCmdKey, u.VMessAuthBlock, u.VMessAuthReady = precomputeVMessAuth(parsed)
	} else if parsed, err := parseUUIDBytes(passwd); err == nil {
		u.UUIDBytes = parsed
		u.HasUUID = true
		u.VMessCmdKey, u.VMessAuthBlock, u.VMessAuthReady = precomputeVMessAuth(parsed)
	} else {
		u.HasUUID = false
		u.VMessAuthReady = false
		u.VMessAuthBlock = nil
	}
	// Primary TrojanHash uses Passwd (and BuildUserIndexForProtocol also indexes UUID when UUID != Passwd)
	sum224 := sha256.Sum224([]byte(passwd))
	hex.Encode(u.TrojanHash[:], sum224[:])
	u.SHA256UUID = sha256.Sum256([]byte(u.UUID))
	u.SHA256Passwd = sha256.Sum256([]byte(u.Passwd))
}

func (u *UserEntry) SetRemainingQuota(remainBytes int64) {
	u.connsMu.Lock()
	u.quotaGen.Add(1)
	if remainBytes < 0 {
		u.hasQuota.Store(false)
		u.quotaRem.Store(0)
		u.connsMu.Unlock()
		return
	}
	u.quotaRem.Store(remainBytes)
	u.hasQuota.Store(true)
	u.connsMu.Unlock()
	if remainBytes == 0 {
		u.DisableAndKick()
	}
}

func (u *UserEntry) IsDisabled() bool {
	return u == nil || u.disabled.Load()
}

// DisableAndKick marks the user disabled and immediately closes all open TCP/UDP/QUIC/Mux connections
// so expired or over-quota accounts cannot continue streaming on pre-existing long-lived sockets.
func (u *UserEntry) DisableAndKick() int {
	if u == nil {
		return 0
	}
	u.connsMu.Lock()
	u.disabled.Store(true)
	conns := u.activeConns
	u.activeConns = nil
	u.connsMu.Unlock()

	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	return len(conns)
}

func (u *UserEntry) disableOnQuotaExhausted(observedGen uint64) {
	if u == nil {
		return
	}
	u.connsMu.Lock()
	// Re-verify under connsMu so a concurrent panel top-up / Reenable() can never be clobbered!
	if u.quotaGen.Load() != observedGen || !u.hasQuota.Load() || u.quotaRem.Load() > 0 {
		u.connsMu.Unlock()
		return
	}
	u.disabled.Store(true)
	conns := u.activeConns
	u.activeConns = nil
	u.connsMu.Unlock()

	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (u *UserEntry) Reenable() {
	if u != nil {
		u.connsMu.Lock()
		u.quotaGen.Add(1)
		u.disabled.Store(false)
		u.connsMu.Unlock()
	}
}

func (u *UserEntry) UpdateLimits(speedLimitBps int64, deviceLimit int, tcpLimit int, dyWhite bool) {
	u.baseSpeedBps.Store(speedLimitBps)
	u.deviceLimit.Store(int32(deviceLimit))
	u.tcpLimit.Store(int32(tcpLimit))
	u.dyWhitelisted.Store(dyWhite)
	if u.throttledUntil.Load() <= time.Now().Unix() {
		u.Limiter.SetBytesPerSec(speedLimitBps)
	}
}

func (u *UserEntry) AddUpload(n int64) {
	if n > 0 {
		u.upBytes.Add(n)
		u.winBytes.Add(n)
		if u.hasQuota.Load() {
			gen := u.quotaGen.Load()
			if u.quotaRem.Add(-n) <= 0 && u.hasQuota.Load() {
				u.disableOnQuotaExhausted(gen)
			}
		}
	}
}

func (u *UserEntry) AddDownload(n int64) {
	if n > 0 {
		u.downBytes.Add(n)
		u.winBytes.Add(n)
		if u.hasQuota.Load() {
			gen := u.quotaGen.Load()
			if u.quotaRem.Add(-n) <= 0 && u.hasQuota.Load() {
				u.disableOnQuotaExhausted(gen)
			}
		}
	}
}

func (u *UserEntry) EffectiveLimiter() *limiter.Bucket {
	if u == nil || u.Limiter == nil || u.Limiter.IsUnlimited() {
		return nil
	}
	return u.Limiter
}

// AcquireConn checks disabled state, TCP stream limits, and online IP device limits.
func (u *UserEntry) AcquireConn(clientIP netip.Addr, ipTTLSec int64, redisLim *redisIPLimiter) error {
	_, err := u.AcquireSession(clientIP, ipTTLSec, redisLim, nil)
	return err
}

// AcquireSession validates user status/limits and registers `closer` so `DisableAndKick()`
// immediately severs active streams the instant the account expires or exceeds traffic quota.
func (u *UserEntry) AcquireSession(clientIP netip.Addr, ipTTLSec int64, redisLim *redisIPLimiter, closer io.Closer) (uint64, error) {
	if u == nil || u.disabled.Load() {
		return 0, ErrUserDisabled
	}
	if u.hasQuota.Load() && u.quotaRem.Load() <= 0 {
		return 0, ErrUserDisabled
	}

	maxTCP := u.tcpLimit.Load()
	if maxTCP > 0 {
		cur := u.activeTCP.Add(1)
		if cur > maxTCP {
			u.activeTCP.Add(-1)
			return 0, ErrTCPLimit
		}
	} else {
		u.activeTCP.Add(1)
	}

	if err := u.checkAndTouchIP(clientIP, ipTTLSec, redisLim); err != nil {
		u.activeTCP.Add(-1)
		return 0, err
	}

	if closer == nil {
		return 0, nil
	}

	cid := u.nextConnID.Add(1)
	u.connsMu.Lock()
	if u.disabled.Load() {
		u.connsMu.Unlock()
		u.activeTCP.Add(-1)
		_ = closer.Close()
		return 0, ErrUserDisabled
	}
	if u.activeConns == nil {
		u.activeConns = make(map[uint64]io.Closer, 4)
	}
	u.activeConns[cid] = closer
	u.connsMu.Unlock()
	return cid, nil
}

// AcquireMuxSession registers an outer multiplexed connection (AnyTLS / Hysteria2) for IP tracking,
// bounded mux session count, and instant DisableAndKick teardown while delegating per-stream TCP limits to AcquireSubStream.
func (u *UserEntry) AcquireMuxSession(clientIP netip.Addr, ipTTLSec int64, redisLim *redisIPLimiter, closer io.Closer) (uint64, error) {
	if u == nil || u.disabled.Load() {
		return 0, ErrUserDisabled
	}
	if u.hasQuota.Load() && u.quotaRem.Load() <= 0 {
		return 0, ErrUserDisabled
	}
	maxMux := int32(64)
	if maxTCP := u.tcpLimit.Load(); maxTCP > 0 && maxTCP < maxMux {
		maxMux = max(maxTCP, 8)
	}
	if u.activeMux.Add(1) > maxMux {
		u.activeMux.Add(-1)
		return 0, ErrTCPLimit
	}
	if err := u.checkAndTouchIP(clientIP, ipTTLSec, redisLim); err != nil {
		u.activeMux.Add(-1)
		return 0, err
	}
	if closer == nil {
		return 0, nil
	}
	cid := u.nextConnID.Add(1)
	u.connsMu.Lock()
	if u.disabled.Load() {
		u.connsMu.Unlock()
		u.activeMux.Add(-1)
		_ = closer.Close()
		return 0, ErrUserDisabled
	}
	if u.activeConns == nil {
		u.activeConns = make(map[uint64]io.Closer, 4)
	}
	u.activeConns[cid] = closer
	u.connsMu.Unlock()
	return cid, nil
}

func (u *UserEntry) ReleaseMuxSession(connID uint64) {
	if u == nil {
		return
	}
	u.activeMux.Add(-1)
	if connID > 0 {
		u.connsMu.Lock()
		if u.activeConns != nil {
			delete(u.activeConns, connID)
		}
		u.connsMu.Unlock()
	}
}

// AcquireUDPSession bounds concurrent per-user UDP NAT sockets (`max 256`) without starving `activeTCP` (`user_tcp_limit`).
func (u *UserEntry) AcquireUDPSession(clientIP netip.Addr, ipTTLSec int64, redisLim *redisIPLimiter, closer io.Closer) (uint64, error) {
	if u == nil || u.disabled.Load() {
		return 0, ErrUserDisabled
	}
	if u.hasQuota.Load() && u.quotaRem.Load() <= 0 {
		return 0, ErrUserDisabled
	}
	if u.activeUDP.Add(1) > 256 {
		u.activeUDP.Add(-1)
		return 0, ErrTCPLimit
	}
	if err := u.checkAndTouchIP(clientIP, ipTTLSec, redisLim); err != nil {
		u.activeUDP.Add(-1)
		return 0, err
	}
	if closer == nil {
		return 0, nil
	}
	cid := u.nextConnID.Add(1)
	u.connsMu.Lock()
	if u.disabled.Load() {
		u.connsMu.Unlock()
		u.activeUDP.Add(-1)
		_ = closer.Close()
		return 0, ErrUserDisabled
	}
	if u.activeConns == nil {
		u.activeConns = make(map[uint64]io.Closer, 4)
	}
	u.activeConns[cid] = closer
	u.connsMu.Unlock()
	return cid, nil
}

func (u *UserEntry) ReleaseUDPSession(connID uint64) {
	if u == nil {
		return
	}
	u.activeUDP.Add(-1)
	if connID > 0 {
		u.connsMu.Lock()
		if u.activeConns != nil {
			delete(u.activeConns, connID)
		}
		u.connsMu.Unlock()
	}
}

func (u *UserEntry) AcquireSubStream() error {
	if u == nil || u.disabled.Load() {
		return ErrUserDisabled
	}
	maxTCP := u.tcpLimit.Load()
	if maxTCP > 0 {
		if u.activeTCP.Add(1) > maxTCP {
			u.activeTCP.Add(-1)
			return ErrTCPLimit
		}
	} else {
		u.activeTCP.Add(1)
	}
	return nil
}

func (u *UserEntry) ReleaseSubStream() {
	if u != nil {
		u.activeTCP.Add(-1)
	}
}

func (u *UserEntry) ReleaseConn() {
	u.activeTCP.Add(-1)
}

func (u *UserEntry) ReleaseSession(connID uint64) {
	if connID > 0 {
		u.connsMu.Lock()
		if u.activeConns != nil {
			delete(u.activeConns, connID)
		}
		u.connsMu.Unlock()
	}
	u.activeTCP.Add(-1)
}

func (u *UserEntry) checkAndTouchIP(ip netip.Addr, ttlSec int64, redisLim *redisIPLimiter) error {
	if !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()
	now := time.Now().Unix()
	devLimit := int(u.deviceLimit.Load())

	// Fast read-lock path: if IP was already recorded within last 5s, skip write lock completely!
	u.ipMu.RLock()
	lastSeen, exists := u.activeIPs[ip]
	u.ipMu.RUnlock()
	if exists && now-lastSeen < 5 {
		return nil
	}

	if devLimit > 0 && redisLim != nil {
		allowed, err := redisLim.CheckAndTouch(u.ID, ip.String(), devLimit, int(ttlSec))
		if err == nil && !allowed {
			return ErrIPLimit
		}
	}

	u.ipMu.Lock()
	defer u.ipMu.Unlock()

	if u.activeIPs == nil {
		u.activeIPs = make(map[netip.Addr]int64, 2)
	}

	cutoff := now - ttlSec
	for k, ts := range u.activeIPs {
		if ts < cutoff {
			delete(u.activeIPs, k)
		}
	}

	if _, ok := u.activeIPs[ip]; ok {
		u.activeIPs[ip] = now
		return nil
	}

	if devLimit > 0 {
		totalDistinct := len(u.activeIPs)
		for rip := range u.remoteIPs {
			if _, localHas := u.activeIPs[rip]; !localHas {
				totalDistinct++
			}
		}
		if rc := int(u.remoteCount.Load()); rc > totalDistinct {
			totalDistinct = rc
		}
		if totalDistinct >= devLimit {
			return ErrIPLimit
		}
	}

	u.activeIPs[ip] = now
	return nil
}

func (u *UserEntry) SetRemoteAliveIPs(ips []string) {
	u.ipMu.Lock()
	defer u.ipMu.Unlock()
	u.remoteCount.Store(0)
	if len(ips) == 0 {
		u.remoteIPs = nil
		return
	}
	m := make(map[netip.Addr]struct{}, len(ips))
	for _, s := range ips {
		if addr, err := netip.ParseAddr(s); err == nil {
			m[addr.Unmap()] = struct{}{}
		}
	}
	u.remoteIPs = m
}

func (u *UserEntry) SetRemoteAliveCount(cnt int) {
	u.ipMu.Lock()
	u.remoteIPs = nil
	if cnt > 0 {
		u.remoteCount.Store(int32(cnt))
	} else {
		u.remoteCount.Store(0)
	}
	u.ipMu.Unlock()
}

func (u *UserEntry) SnapshotAliveIPs(ttlSec int64) []string {
	u.ipMu.RLock()
	empty := len(u.activeIPs) == 0
	u.ipMu.RUnlock()
	if empty {
		return nil
	}

	now := time.Now().Unix()
	cutoff := now - ttlSec

	u.ipMu.Lock()
	defer u.ipMu.Unlock()
	for k, ts := range u.activeIPs {
		if ts < cutoff {
			delete(u.activeIPs, k)
		}
	}
	if len(u.activeIPs) == 0 {
		return nil
	}
	out := make([]string, 0, len(u.activeIPs))
	for k := range u.activeIPs {
		out = append(out, k.String())
	}
	return out
}

// Tracker manages all active UserEntries, atomic traffic harvesting, node rate limiting,
// dynamic speed throttling, and optional Redis global IP limiting.
type Tracker struct {
	cfg         *config.Config
	NodeLimiter *limiter.Bucket
	redisLim    *redisIPLimiter

	mu             sync.RWMutex
	users          map[int]*UserEntry
	retiredMu      sync.Mutex
	retiredTraffic []TrafficDelta // final unpushed traffic harvested from expired/kicked users
}

func NewTracker(cfg *config.Config) *Tracker {
	t := &Tracker{
		cfg:         cfg,
		NodeLimiter: limiter.NewBucketMbps(cfg.NodeSpeedLimit),
		users:       make(map[int]*UserEntry),
	}
	if cfg.DeviceLimitEnable && cfg.RedisIPLimitEnable && cfg.RedisIPLimitAddr != "" {
		t.redisLim = newRedisIPLimiter(cfg)
	}
	return t
}

func (t *Tracker) RedisLimiter() *redisIPLimiter {
	return t.redisLim
}

func (t *Tracker) IPTTLSeconds() int64 {
	ttl := int64(t.cfg.SubmitInterval) + 15
	if t.cfg.RedisIPLimitEnable && t.cfg.RedisIPLimitExpiry > 0 {
		ttl = int64(t.cfg.RedisIPLimitExpiry)
	}
	if ttl < 30 {
		ttl = 30
	}
	return ttl
}

// SyncUserSpec describes a user pulled from the panel.
type SyncUserSpec struct {
	ID             int
	UUIDOrPass     string
	AltPasswd      string // optional secondary credential (e.g. SSPanel passwd alongside uuid)
	SpeedLimit     int64  // bytes/sec from panel (0 = unlimited)
	DeviceLimit    int    // max IPs from panel (0 = unlimited)
	RemainBytes    int64  // <=0: unlimited / panel-polled; >0: real-time byte-exact remaining cap
	QuotaExhausted bool   // true when panel reports u + d >= transfer_enable
}

// ReconcileUsers performs an incremental O(N) diff: existing users preserve their UserEntry
// pointer, active connections, rate limiters, and unpushed atomic traffic counters.
// Users removed by the panel (expired, banned, or over traffic quota) have their final unpushed
// bytes captured and ALL active TCP/UDP/QUIC/Mux connections immediately force-closed (`DisableAndKick`).
func (t *Tracker) ReconcileUsers(specs []SyncUserSpec) (entries []*UserEntry, added, updated, removed int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seen := make(map[int]struct{}, len(specs))
	entries = make([]*UserEntry, 0, len(specs))

	staticSpeedBps := int64(t.cfg.UserSpeedLimit * 125000.0)

	for _, sp := range specs {
		if sp.QuotaExhausted {
			continue
		}
		seen[sp.ID] = struct{}{}
		effSpeed := sp.SpeedLimit
		if staticSpeedBps > 0 && (effSpeed <= 0 || staticSpeedBps < effSpeed) {
			effSpeed = staticSpeedBps
		}
		effDev := 0
		if t.cfg.DeviceLimitEnable {
			effDev = sp.DeviceLimit
			if t.cfg.UserConnLimit > 0 && (effDev <= 0 || t.cfg.UserConnLimit < effDev) {
				effDev = t.cfg.UserConnLimit
			}
		}
		_, dyWhite := t.cfg.DyLimitWhiteUserIDs[sp.ID]

		wantUUID := sp.UUIDOrPass
		wantPass := sp.UUIDOrPass
		if sp.AltPasswd != "" {
			wantPass = sp.AltPasswd
		}
		if wantUUID == "" {
			wantUUID = wantPass
		}

		if existing, ok := t.users[sp.ID]; ok {
			if existing.UUID != wantUUID || existing.Passwd != wantPass {
				// Credential reset/rotation: immediately sever pre-existing sessions using the old leaked secret,
				// carry over unpushed bytes, and swap in an immutable fresh UserEntry (zero data races!).
				existing.DisableAndKick()
				prevUp := existing.upBytes.Swap(0)
				prevDown := existing.downBytes.Swap(0)

				u := NewUserEntry(sp.ID, wantUUID, effSpeed, effDev, t.cfg.UserTCPLimit, dyWhite)
				if wantPass != wantUUID {
					u.RefreshDualKeys(wantUUID, wantPass)
				}
				if prevUp > 0 {
					u.upBytes.Add(prevUp)
				}
				if prevDown > 0 {
					u.downBytes.Add(prevDown)
				}
				if sp.RemainBytes > 0 {
					rem := sp.RemainBytes - (prevUp + prevDown)
					if rem <= 0 {
						u.SetRemainingQuota(0)
					} else {
						u.SetRemainingQuota(rem)
					}
				}
				t.users[sp.ID] = u
				entries = append(entries, u)
				updated++
				continue
			}

			wasDisabled := existing.IsDisabled()
			existing.UpdateLimits(effSpeed, effDev, t.cfg.UserTCPLimit, dyWhite)
			if sp.RemainBytes > 0 {
				// Subtract local unpushed bytes so a pull running before PushTraffic never re-enables an over-quota user!
				unpushed := existing.upBytes.Load() + existing.downBytes.Load()
				rem := sp.RemainBytes - unpushed
				if rem <= 0 {
					existing.SetRemainingQuota(0)
				} else {
					existing.SetRemainingQuota(rem)
					existing.Reenable()
				}
			} else {
				existing.SetRemainingQuota(-1)
				existing.Reenable()
			}
			if wasDisabled != existing.IsDisabled() {
				updated++
			}
			entries = append(entries, existing)
		} else {
			u := NewUserEntry(sp.ID, wantUUID, effSpeed, effDev, t.cfg.UserTCPLimit, dyWhite)
			if wantPass != wantUUID {
				u.RefreshDualKeys(wantUUID, wantPass)
			}
			if sp.RemainBytes > 0 {
				u.SetRemainingQuota(sp.RemainBytes)
			}
			t.users[sp.ID] = u
			entries = append(entries, u)
			added++
		}
	}

	var retired []TrafficDelta
	for id, u := range t.users {
		if _, ok := seen[id]; !ok {
			// Immediately sever all open sockets belonging to this expired / over-quota user!
			u.DisableAndKick()
			up := u.upBytes.Swap(0)
			down := u.downBytes.Swap(0)
			if up+down > 0 {
				retired = append(retired, TrafficDelta{
					UserID:   id,
					Upload:   up,
					Download: down,
				})
			}
			delete(t.users, id)
			removed++
		}
	}
	if len(retired) > 0 {
		t.retiredMu.Lock()
		t.retiredTraffic = append(t.retiredTraffic, retired...)
		t.retiredMu.Unlock()
	}
	return entries, added, updated, removed
}

// HarvestTraffic atomically swaps out non-zero upload/download byte counters (including kicked users' final bytes).
func (t *Tracker) HarvestTraffic(minBytes int64) []TrafficDelta {
	var batch []TrafficDelta
	t.retiredMu.Lock()
	if len(t.retiredTraffic) > 0 {
		batch = append(batch, t.retiredTraffic...)
		t.retiredTraffic = nil
	}
	t.retiredMu.Unlock()

	t.mu.RLock()
	defer t.mu.RUnlock()

	for id, u := range t.users {
		up := u.upBytes.Swap(0)
		down := u.downBytes.Swap(0)
		if up+down <= minBytes {
			if up > 0 {
				u.upBytes.Add(up)
			}
			if down > 0 {
				u.downBytes.Add(down)
			}
			continue
		}
		batch = append(batch, TrafficDelta{
			UserID:   id,
			Upload:   up,
			Download: down,
		})
	}
	return batch
}

// RollbackTraffic restores harvested bytes if pushing to the panel fails.
func (t *Tracker) RollbackTraffic(batch []TrafficDelta) {
	t.mu.RLock()
	var unmatched []TrafficDelta
	for _, item := range batch {
		if u, ok := t.users[item.UserID]; ok {
			u.upBytes.Add(item.Upload)
			u.downBytes.Add(item.Download)
		} else {
			unmatched = append(unmatched, item)
		}
	}
	t.mu.RUnlock()

	if len(unmatched) > 0 {
		t.retiredMu.Lock()
		t.retiredTraffic = append(t.retiredTraffic, unmatched...)
		t.retiredMu.Unlock()
	}
}

// SnapshotAliveMap returns userID -> []ip for all currently active users.
func (t *Tracker) SnapshotAliveMap() map[int][]string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ttl := t.IPTTLSeconds()
	res := make(map[int][]string)
	for id, u := range t.users {
		if ips := u.SnapshotAliveIPs(ttl); len(ips) > 0 {
			res[id] = ips
		}
	}
	return res
}

// ApplyRemoteAliveList updates panel-wide device state (from UniProxy /alivelist IP lists).
func (t *Tracker) ApplyRemoteAliveList(alive map[int][]string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for id, u := range t.users {
		u.SetRemoteAliveIPs(alive[id])
	}
}

// ApplyRemoteAliveCounts updates panel-wide integer device counts (from Xboard / NewV2Board /alivelist).
func (t *Tracker) ApplyRemoteAliveCounts(counts map[int]int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for id, u := range t.users {
		u.SetRemoteAliveCount(counts[id])
	}
}

// TickDynamicSpeedLimit evaluates sliding 1-second throughput per user when dy_limit_enable=true.
func (t *Tracker) TickDynamicSpeedLimit() {
	if !t.cfg.DyLimitEnable {
		return
	}
	triggerBps := int64(t.cfg.DyLimitTriggerSpeed * 125000.0)
	throttleBps := int64(t.cfg.DyLimitSpeed * 125000.0)
	if throttleBps <= 0 {
		throttleBps = 125000 // never set 0 (unlimited) during dynamic penalty!
	}
	triggerSec := int32(t.cfg.DyLimitTriggerTime)
	throttleDur := int64(t.cfg.DyLimitTime)
	now := time.Now().Unix()

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, u := range t.users {
		secBytes := u.winBytes.Swap(0)
		if u.dyWhitelisted.Load() {
			continue
		}
		until := u.throttledUntil.Load()
		if until > 0 {
			if now >= until {
				u.throttledUntil.Store(0)
				u.overSpeedSec.Store(0)
				u.Limiter.SetBytesPerSec(u.baseSpeedBps.Load())
			}
			continue
		}
		if secBytes >= triggerBps {
			cnt := u.overSpeedSec.Add(1)
			if cnt >= triggerSec {
				u.throttledUntil.Store(now + throttleDur)
				u.overSpeedSec.Store(0)
				u.Limiter.SetBytesPerSec(throttleBps)
			}
		} else if u.overSpeedSec.Load() > 0 {
			u.overSpeedSec.Add(-1)
		}
	}
}

func parseUUIDBytes(s string) ([16]byte, error) {
	var out [16]byte
	var hexBuf [32]byte
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		if j >= 32 {
			return out, errors.New("uuid too long")
		}
		hexBuf[j] = c
		j++
	}
	if j != 32 {
		return out, errors.New("invalid uuid length")
	}
	_, err := hex.Decode(out[:], hexBuf[:])
	return out, err
}

// redisIPLimiter implements a minimal, zero-dependency Redis RESP2 client with persistent
// keep-alive connection reuse for global IP limiting across multi-node clusters.
type redisIPLimiter struct {
	addr   string
	passwd string
	db     int
	useTLS bool

	mu   sync.Mutex
	conn net.Conn
	br   *bufio.Reader
}

func newRedisIPLimiter(cfg *config.Config) *redisIPLimiter {
	return &redisIPLimiter{
		addr:   cfg.RedisIPLimitAddr,
		passwd: cfg.RedisIPLimitPassword,
		db:     cfg.RedisIPLimitDB,
		useTLS: cfg.RedisIPLimitTLS,
	}
}

func (r *redisIPLimiter) dialLocked() error {
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
		r.br = nil
	}
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond, KeepAlive: 45 * time.Second}
	var conn net.Conn
	var err error
	if r.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", r.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", r.addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	br := bufio.NewReaderSize(conn, 512)
	if r.passwd != "" {
		if _, err := writeRESP(conn, "AUTH", r.passwd); err != nil {
			_ = conn.Close()
			return err
		}
		if _, err := readRESPLine(br); err != nil {
			_ = conn.Close()
			return err
		}
	}
	if r.db > 0 {
		if _, err := writeRESP(conn, "SELECT", strconv.Itoa(r.db)); err != nil {
			_ = conn.Close()
			return err
		}
		if _, err := readRESPLine(br); err != nil {
			_ = conn.Close()
			return err
		}
	}
	r.conn = conn
	r.br = br
	return nil
}

func (r *redisIPLimiter) CheckAndTouch(userID int, ip string, maxIPs int, expirySec int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if r.conn == nil {
			if err := r.dialLocked(); err != nil {
				return true, err
			}
		}
		allowed, err := r.execPipelineLocked(userID, ip, maxIPs, expirySec)
		if err == nil {
			return allowed, nil
		}
		_ = r.conn.Close()
		r.conn = nil
		r.br = nil
	}
	return true, errors.New("redis pipeline failed after reconnect")
}

func (r *redisIPLimiter) execPipelineLocked(userID int, ip string, maxIPs int, expirySec int) (bool, error) {
	_ = r.conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	now := time.Now().Unix()
	key := fmt.Sprintf("xoga:ip:%d", userID)
	minScore := strconv.FormatInt(now-int64(expirySec), 10)
	nowStr := strconv.FormatInt(now, 10)
	expStr := strconv.Itoa(expirySec + 10)

	var sb strings.Builder
	appendRESP(&sb, "ZREMRANGEBYSCORE", key, "-inf", minScore)
	appendRESP(&sb, "ZADD", key, nowStr, ip)
	appendRESP(&sb, "ZCARD", key)
	appendRESP(&sb, "EXPIRE", key, expStr)

	if _, err := r.conn.Write([]byte(sb.String())); err != nil {
		return true, err
	}
	if _, err := readRESPLine(r.br); err != nil {
		return true, err
	}
	zaddLine, err := readRESPLine(r.br)
	if err != nil {
		return true, err
	}
	cardLine, err := readRESPLine(r.br)
	if err != nil {
		return true, err
	}
	if _, err := readRESPLine(r.br); err != nil {
		return true, err
	}
	if strings.HasPrefix(cardLine, ":") {
		cnt, _ := strconv.Atoi(strings.TrimSpace(cardLine[1:]))
		if cnt > maxIPs {
			// Remove newly inserted rejected IP immediately so it never pollutes the ZSET or locks out valid devices!
			if strings.TrimSpace(zaddLine) == ":1" {
				if _, werr := writeRESP(r.conn, "ZREM", key, ip); werr != nil {
					return false, werr
				}
				if _, rerr := readRESPLine(r.br); rerr != nil {
					return false, rerr
				}
			}
			return false, nil
		}
	}
	return true, nil
}

func appendRESP(sb *strings.Builder, args ...string) {
	sb.WriteByte('*')
	sb.WriteString(strconv.Itoa(len(args)))
	sb.WriteString("\r\n")
	for _, a := range args {
		sb.WriteByte('$')
		sb.WriteString(strconv.Itoa(len(a)))
		sb.WriteString("\r\n")
		sb.WriteString(a)
		sb.WriteString("\r\n")
	}
}

func writeRESP(w net.Conn, args ...string) (int, error) {
	var sb strings.Builder
	appendRESP(&sb, args...)
	return w.Write([]byte(sb.String()))
}

func readRESPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(line, "-") {
		return line, errors.New(strings.TrimSpace(line[1:]))
	}
	if strings.HasPrefix(line, "$") {
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		if n >= 0 {
			buf := make([]byte, n+2)
			_, err = io.ReadFull(br, buf)
			return string(buf[:n]), err
		}
	}
	return strings.TrimSpace(line), nil
}
