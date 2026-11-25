package protocol

import (
	"net/netip"
	"sync/atomic"
)

const ipHintSlots = 4096 // power of two; 4096 * 8 bytes = 32 KiB fixed lock-free table

// ipHintCache is a zero-allocation, lock-free direct-mapped cache mapping client IP -> user slice index
// (inspired by soga's `ip-user-cache-vmess` & shadowsocks-rust session hints, but 100% in-memory with zero disk I/O).
// On 5,000+ user VMess / Classic-SS nodes, repeat connections from active IPs authenticate in O(1) (1 cipher op).
type ipHintCache struct {
	slots [ipHintSlots]atomic.Uint64
}

func ipTag32(ip netip.Addr) uint32 {
	b := ip.As16()
	// Fast FNV-1a 32-bit over 16-byte stack value (0 heap allocations)
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
