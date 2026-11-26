package protocol

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

const (
	replayWords      = 16384             // 16384 * 64 = 1,048,576 bits (128 KiB per generation, <0.02% FP at 500 conn/s)
	replayBitMask    = replayWords*64 - 1
	replayWindowSecs = 65
)

// replayFilter implements a lock-free dual-generation rotating atomic Bloom filter (modeled after
// xray-core TimedUserValidator & shadowsocks-rust salt replay filter) to detect and block replayed
// VMess AuthIDs and Shadowsocks stream salts in O(1) with zero heap allocations.
type replayFilter struct {
	gens     [2][replayWords]atomic.Uint64
	active   atomic.Uint32
	rotateAt atomic.Int64
	rotMu    sync.Mutex
}

// CheckAndMark records a >=16-byte handshake token (AuthID or stream salt) and returns true
// if it was already observed within the active replay window. Must only be called AFTER
// cryptographic user authentication succeeds so unauthenticated probes cannot pollute the filter.
func (f *replayFilter) CheckAndMark(token []byte) bool {
	if len(token) < 16 {
		return false
	}
	now := time.Now().Unix()
	rot := f.rotateAt.Load()
	if rot == 0 {
		if f.rotateAt.CompareAndSwap(0, now+replayWindowSecs) {
			rot = now + replayWindowSecs
		} else {
			rot = f.rotateAt.Load()
		}
	} else if now >= rot {
		f.maybeRotate(now)
	}

	h1 := splitMix64(binary.LittleEndian.Uint64(token[0:8]))
	h2 := splitMix64(binary.LittleEndian.Uint64(token[8:16]))
	if h2 == 0 {
		h2 = 0x9e3779b97f4a7c15
	}

	curIdx := f.active.Load() & 1
	prevIdx := curIdx ^ 1
	curGen := &f.gens[curIdx]
	prevGen := &f.gens[prevIdx]

	allInCur := true
	allInPrev := true

	for i := uint64(0); i < 4; i++ {
		bit := (h1 + i*h2) & replayBitMask
		word := bit >> 6
		mask := uint64(1) << (bit & 63)

		oldCur := curGen[word].Or(mask)
		if (oldCur & mask) == 0 {
			allInCur = false
		}
		if (prevGen[word].Load() & mask) == 0 {
			allInPrev = false
		}
	}
	return allInCur || allInPrev
}

func (f *replayFilter) maybeRotate(now int64) {
	if !f.rotMu.TryLock() {
		return
	}
	defer f.rotMu.Unlock()
	if now < f.rotateAt.Load() {
		return
	}
	nextIdx := (f.active.Load() + 1) & 1
	for i := 0; i < replayWords; i++ {
		f.gens[nextIdx][i].Store(0)
	}
	f.active.Store(nextIdx)
	f.rotateAt.Store(now + replayWindowSecs)
}

func splitMix64(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}
