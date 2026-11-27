package protocol

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// legacyAuthWindow is the accepted clock offset for legacy MD5 AuthIDs. V2Ray-style
// legacy clients randomize their timestamp by up to ±30 seconds; the extra margin
// covers client clock drift.
const legacyAuthWindow = 60

// legacyBucket maps every user's legacy AuthID for a single Unix second.
type legacyBucket struct {
	ts      int64
	entries map[[16]byte]*VMessUserEntry
}

// legacyTable is an immutable ring snapshot of 2*legacyAuthWindow+1 per-second buckets.
type legacyTable struct {
	idx     *UserIndex
	buckets []*legacyBucket
}

// legacyAuthCache implements Soga-compatible `vmess auth mode: auto`: it accepts
// primary-UUID legacy MD5 AuthIDs for every VMess user, alongside AEAD.
type legacyAuthCache struct {
	table   atomic.Pointer[legacyTable]
	mu      sync.Mutex
	started atomic.Bool
	stop    chan struct{}
}

func buildLegacyBucket(idx *UserIndex, ts int64) *legacyBucket {
	b := &legacyBucket{ts: ts, entries: make(map[[16]byte]*VMessUserEntry, len(idx.VMessUsers))}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ts))
	var tag [16]byte
	for i := range idx.VMessUsers {
		entry := &idx.VMessUsers[i]
		id := entry.User.UUIDBytes
		mac := hmac.New(md5.New, id[:])
		_, _ = mac.Write(stamp[:])
		mac.Sum(tag[:0])
		b.entries[tag] = entry
	}
	return b
}

// refresh brings the ring up to date for `idx` at time `now`, reusing buckets that
// are still inside the window when the user index is unchanged.
func (c *legacyAuthCache) refresh(idx *UserIndex, now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx == nil {
		c.table.Store(nil)
		return
	}
	old := c.table.Load()
	reuse := map[int64]*legacyBucket{}
	if old != nil && old.idx == idx {
		for _, b := range old.buckets {
			reuse[b.ts] = b
		}
	}
	buckets := make([]*legacyBucket, 0, 2*legacyAuthWindow+1)
	for ts := now - legacyAuthWindow; ts <= now+legacyAuthWindow; ts++ {
		if b, ok := reuse[ts]; ok {
			buckets = append(buckets, b)
		} else {
			buckets = append(buckets, buildLegacyBucket(idx, ts))
		}
	}
	c.table.Store(&legacyTable{idx: idx, buckets: buckets})
}

// lookup returns the matching user and the 8-byte timestamp used by the legacy header IV.
func (c *legacyAuthCache) lookup(authID [16]byte) (*VMessUserEntry, [8]byte, bool) {
	var stamp [8]byte
	t := c.table.Load()
	if t == nil {
		return nil, stamp, false
	}
	for _, b := range t.buckets {
		if entry, ok := b.entries[authID]; ok {
			binary.BigEndian.PutUint64(stamp[:], uint64(b.ts))
			return entry, stamp, true
		}
	}
	return nil, stamp, false
}

// start launches the once-per-second ring refresher.
func (c *legacyAuthCache) start(current func() *UserIndex) {
	if !c.started.CompareAndSwap(false, true) {
		return
	}
	c.stop = make(chan struct{})
	c.refresh(current(), time.Now().Unix())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-ticker.C:
				c.refresh(current(), time.Now().Unix())
			}
		}
	}()
}

func (c *legacyAuthCache) close() {
	if c.started.Load() && c.stop != nil {
		select {
		case <-c.stop:
		default:
			close(c.stop)
		}
	}
}
