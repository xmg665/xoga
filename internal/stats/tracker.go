package stats

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
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
	// Immutable / rarely-updated identity
	ID         int
	UUID       string
	Passwd     string
	UUIDBytes  [16]byte
	HasUUID    bool
	TrojanHash [56]byte // hex-encoded SHA-224 of password/UUID

	// Cache-line padding before hot atomic traffic counters
	_ [64]byte

	upBytes   atomic.Int64
	downBytes atomic.Int64
	winBytes  atomic.Int64 // bytes accumulated during current dynamic limit tick
	activeTCP atomic.Int32

	_ [64]byte

	// Limits & dynamic speed limit state
	baseSpeedBps    atomic.Int64
	deviceLimit     atomic.Int32
	tcpLimit        atomic.Int32
	overSpeedSec    atomic.Int32
	throttledUntil  atomic.Int64 // Unix seconds
	dyWhitelisted   atomic.Bool
	Limiter         *limiter.Bucket

	// Per-user active client IPs (netip.Addr is a 24-byte comparable value -> 0 string allocs)
	ipMu       sync.RWMutex
	activeIPs  map[netip.Addr]int64 // lastSeen Unix seconds
	remoteIPs  map[netip.Addr]struct{}
}

func NewUserEntry(id int, uuidOrPass string, speedLimitBps int64, deviceLimit int, tcpLimit int, dyWhite bool) *UserEntry {
	u := &UserEntry{
		ID:        id,
		UUID:      uuidOrPass,
		Passwd:    uuidOrPass,
		Limiter:   limiter.NewBucketBps(speedLimitBps),
		activeIPs: make(map[netip.Addr]int64, 4),
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
	} else {
		u.HasUUID = false
	}
	sum224 := sha256.Sum224([]byte(uuidOrPass))
	hex.Encode(u.TrojanHash[:], sum224[:])
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
	}
}

func (u *UserEntry) AddDownload(n int64) {
	if n > 0 {
		u.downBytes.Add(n)
		u.winBytes.Add(n)
	}
}

func (u *UserEntry) EffectiveLimiter() *limiter.Bucket {
	if u == nil || u.Limiter == nil || u.Limiter.IsUnlimited() {
		return nil
	}
	return u.Limiter
}

// AcquireConn checks TCP stream limits and online IP device limits before accepting a session.
func (u *UserEntry) AcquireConn(clientIP netip.Addr, ipTTLSec int64, redisLim *redisIPLimiter) error {
	maxTCP := u.tcpLimit.Load()
	if maxTCP > 0 {
		cur := u.activeTCP.Add(1)
		if cur > maxTCP {
			u.activeTCP.Add(-1)
			return ErrTCPLimit
		}
	} else {
		u.activeTCP.Add(1)
	}

	if err := u.checkAndTouchIP(clientIP, ipTTLSec, redisLim); err != nil {
		u.activeTCP.Add(-1)
		return err
	}
	return nil
}

func (u *UserEntry) ReleaseConn() {
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

func (u *UserEntry) SnapshotAliveIPs(ttlSec int64) []string {
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

	mu    sync.RWMutex
	users map[int]*UserEntry
}

func NewTracker(cfg *config.Config) *Tracker {
	t := &Tracker{
		cfg:         cfg,
		NodeLimiter: limiter.NewBucketMbps(cfg.NodeSpeedLimit),
		users:       make(map[int]*UserEntry),
	}
	if cfg.RedisIPLimitEnable && cfg.RedisIPLimitAddr != "" {
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
	ID          int
	UUIDOrPass  string
	SpeedLimit  int64 // bytes/sec from panel (0 = unlimited)
	DeviceLimit int   // max IPs from panel (0 = unlimited)
}

// ReconcileUsers performs an incremental O(N) diff: existing users preserve their UserEntry
// pointer, active connections, rate limiters, and unpushed atomic traffic counters.
func (t *Tracker) ReconcileUsers(specs []SyncUserSpec) (entries []*UserEntry, added, updated, removed int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seen := make(map[int]struct{}, len(specs))
	entries = make([]*UserEntry, 0, len(specs))

	staticSpeedBps := int64(t.cfg.UserSpeedLimit * 125000.0)

	for _, sp := range specs {
		seen[sp.ID] = struct{}{}
		effSpeed := sp.SpeedLimit
		if staticSpeedBps > 0 && (effSpeed <= 0 || staticSpeedBps < effSpeed) {
			effSpeed = staticSpeedBps
		}
		effDev := sp.DeviceLimit
		if t.cfg.UserConnLimit > 0 && (effDev <= 0 || t.cfg.UserConnLimit < effDev) {
			effDev = t.cfg.UserConnLimit
		}
		_, dyWhite := t.cfg.DyLimitWhiteUserIDs[sp.ID]

		if existing, ok := t.users[sp.ID]; ok {
			if existing.UUID != sp.UUIDOrPass {
				existing.RefreshKeys(sp.UUIDOrPass)
				updated++
			}
			existing.UpdateLimits(effSpeed, effDev, t.cfg.UserTCPLimit, dyWhite)
			entries = append(entries, existing)
		} else {
			u := NewUserEntry(sp.ID, sp.UUIDOrPass, effSpeed, effDev, t.cfg.UserTCPLimit, dyWhite)
			t.users[sp.ID] = u
			entries = append(entries, u)
			added++
		}
	}

	for id := range t.users {
		if _, ok := seen[id]; !ok {
			delete(t.users, id)
			removed++
		}
	}
	return entries, added, updated, removed
}

// HarvestTraffic atomically swaps out non-zero upload/download byte counters.
func (t *Tracker) HarvestTraffic(minBytes int64) []TrafficDelta {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var batch []TrafficDelta
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
	defer t.mu.RUnlock()
	for _, item := range batch {
		if u, ok := t.users[item.UserID]; ok {
			u.upBytes.Add(item.Upload)
			u.downBytes.Add(item.Download)
		}
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

// ApplyRemoteAliveList updates panel-wide device state (from UniProxy /alivelist).
func (t *Tracker) ApplyRemoteAliveList(alive map[int][]string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for id, u := range t.users {
		u.SetRemoteAliveIPs(alive[id])
	}
}

// TickDynamicSpeedLimit evaluates sliding 1-second throughput per user when dy_limit_enable=true.
func (t *Tracker) TickDynamicSpeedLimit() {
	if !t.cfg.DyLimitEnable {
		return
	}
	triggerBps := int64(t.cfg.DyLimitTriggerSpeed * 125000.0)
	throttleBps := int64(t.cfg.DyLimitSpeed * 125000.0)
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

// redisIPLimiter implements a minimal, zero-dependency Redis RESP2 client for global IP limiting.
type redisIPLimiter struct {
	addr   string
	passwd string
	db     int
	useTLS bool
}

func newRedisIPLimiter(cfg *config.Config) *redisIPLimiter {
	return &redisIPLimiter{
		addr:   cfg.RedisIPLimitAddr,
		passwd: cfg.RedisIPLimitPassword,
		db:     cfg.RedisIPLimitDB,
		useTLS: cfg.RedisIPLimitTLS,
	}
}

func (r *redisIPLimiter) CheckAndTouch(userID int, ip string, maxIPs int, expirySec int) (bool, error) {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	var conn net.Conn
	var err error
	if r.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", r.addr, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.Dial("tcp", r.addr)
	}
	if err != nil {
		return true, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	br := bufio.NewReaderSize(conn, 512)
	if r.passwd != "" {
		if _, err := writeRESP(conn, "AUTH", r.passwd); err != nil {
			return true, err
		}
		if _, err := readRESPLine(br); err != nil {
			return true, err
		}
	}
	if r.db > 0 {
		if _, err := writeRESP(conn, "SELECT", strconv.Itoa(r.db)); err != nil {
			return true, err
		}
		if _, err := readRESPLine(br); err != nil {
			return true, err
		}
	}

	now := time.Now().Unix()
	key := fmt.Sprintf("xoga:ip:%d", userID)
	minScore := strconv.FormatInt(now-int64(expirySec), 10)
	nowStr := strconv.FormatInt(now, 10)
	expStr := strconv.Itoa(expirySec + 10)

	// Pipeline 4 commands in one write syscall
	var sb strings.Builder
	appendRESP(&sb, "ZREMRANGEBYSCORE", key, "-inf", minScore)
	appendRESP(&sb, "ZADD", key, nowStr, ip)
	appendRESP(&sb, "ZCARD", key)
	appendRESP(&sb, "EXPIRE", key, expStr)

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return true, err
	}
	_, _ = readRESPLine(br) // ZREMRANGEBYSCORE reply
	_, _ = readRESPLine(br) // ZADD reply
	cardLine, err := readRESPLine(br)
	_, _ = readRESPLine(br) // EXPIRE reply
	if err != nil {
		return true, err
	}
	if strings.HasPrefix(cardLine, ":") {
		cnt, _ := strconv.Atoi(strings.TrimSpace(cardLine[1:]))
		if cnt > maxIPs {
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
			_, err = br.Read(buf)
			return string(buf[:n]), err
		}
	}
	return strings.TrimSpace(line), nil
}
