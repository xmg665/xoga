package protocol

import (
	"net/netip"
	"sync/atomic"
)

const (
	ipHintSlots = 4096 // power of two; 4096 * 8 bytes = 32 KiB fixed lock-free table
	hotRingSize = 1024 // 1024 * 4 bytes = 4 KiB L1-resident active user index ring (supports 1000+ active users/node)
)

// ipHintCache is a zero-allocation, lock-free direct-mapped cache mapping client IP -> user slice index.
// When unique client IPs are visible (direct / ProxyProtocol / X-Forwarded-For), repeat connections
// authenticate in O(1) (1 cipher op).
type ipHintCache struct {
	slots [ipHintSlots]atomic.Uint64
}

func ipTag32(ip netip.Addr) uint32 {
	b := ip.As16()
	var h uint32 = 2166136261
	for i := 0; i < 16; i++ {
		h ^= uint32(b[i])
		h *= 16777619
	}
	if h == 0 {
		h = 1
	}
	return h
}

func (c *ipHintCache) Lookup(ip netip.Addr) (int, bool) {
	if !ip.IsValid() {
		return 0, false
	}
	tag := ipTag32(ip)
	packed := c.slots[tag&(ipHintSlots-1)].Load()
	if packed == 0 || uint32(packed>>32) != tag {
		return 0, false
	}
	return int(uint32(packed)), true
}

func (c *ipHintCache) Store(ip netip.Addr, idx int) {
	if !ip.IsValid() || idx < 0 {
		return
	}
	tag := ipTag32(ip)
	packed := (uint64(tag) << 32) | uint64(uint32(idx))
	c.slots[tag&(ipHintSlots-1)].Store(packed)
}

// hotUserRing caches up to 256 recently active user indices in a 1 KiB L1-cache-resident lock-free array.
// Crucial for L4 TCP transit relays where thousands of connections from 50-150 active users arrive
// sharing the exact same relay source IP (so IP-based hints collide): reduces 5,000+ user scans to ~25 checks
// with zero atomic writes once active users are resident in the ring.
type hotUserRing struct {
	slots  [hotRingSize]atomic.Int32 // stores idx+1 (0 means empty)
	cursor atomic.Uint32
}

func (r *hotUserRing) Promote(idx int) {
	if idx < 0 {
		return
	}
	target := int32(idx + 1)
	for i := 0; i < hotRingSize; i++ {
		v := r.slots[i].Load()
		if v == target {
			return // already resident -> avoid cache-line write invalidation across cores!
		}
		if v == 0 {
			if r.slots[i].CompareAndSwap(0, target) {
				return
			}
		}
	}
	pos := r.cursor.Add(1) & (hotRingSize - 1)
	r.slots[pos].Store(target)
}

func (r *hotUserRing) Reset() {
	for i := 0; i < hotRingSize; i++ {
		r.slots[i].Store(0)
	}
}
