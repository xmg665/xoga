package limiter

import (
	"io"
	"sync/atomic"
	"time"
)

// Bucket implements a lock-free Generic Cell Rate Algorithm (GCRA) bandwidth limiter.
// Unlike mutex-based token buckets, hot-path checks use a single atomic CAS on a nanosecond
// virtual arrival timestamp with zero heap allocations and zero background goroutines.
type Bucket struct {
	rateBps      atomic.Int64  // bytes per second; <= 0 means unlimited
	nextFreeNano atomic.Int64  // virtual scheduling timestamp (UnixNano)
	epoch        atomic.Uint64 // incremented when rate increases or becomes unlimited
}

func NewBucketMbps(mbps float64) *Bucket {
	b := &Bucket{}
	b.SetMbps(mbps)
	return b
}

func NewBucketBps(bps int64) *Bucket {
	b := &Bucket{}
	b.SetBytesPerSec(bps)
	return b
}

// SetMbps updates the rate limit in Megabits per second (1 Mbps = 125,000 bytes/sec).
func (b *Bucket) SetMbps(mbps float64) {
	if mbps <= 0 {
		b.SetBytesPerSec(0)
		return
	}
	bps := int64(mbps * 125000.0)
	if bps < 1024 {
		bps = 1024
	}
	b.SetBytesPerSec(bps)
}

func (b *Bucket) SetBytesPerSec(bps int64) {
	if bps <= 0 {
		b.rateBps.Store(0)
		b.nextFreeNano.Store(0)
		b.epoch.Add(1)
		return
	}
	prev := b.rateBps.Swap(bps)
	if bps > prev {
		// Clamp accumulated future debt when rate limit increases (e.g., exiting dynamic penalty)
		now := time.Now().UnixNano()
		if b.nextFreeNano.Load() > now+int64(250*time.Millisecond) {
			b.nextFreeNano.Store(now)
		}
		b.epoch.Add(1)
	}
}

func (b *Bucket) BytesPerSec() int64 {
	if b == nil {
		return 0
	}
	return b.rateBps.Load()
}

func (b *Bucket) IsUnlimited() bool {
	return b == nil || b.rateBps.Load() <= 0
}

// Wait blocks until n bytes are permitted by the rate limit.
func (b *Bucket) Wait(n int) {
	if b == nil || n <= 0 {
		return
	}
	const (
		burstWindowNano   = int64(250 * time.Millisecond)
		maxQueueDelayNano = int64(2 * time.Second)
		sleepStepNano     = int64(200 * time.Millisecond)
	)

	var targetNano int64
	var startEpoch uint64
	for {
		startEpoch = b.epoch.Load()
		bps := b.rateBps.Load()
		if bps <= 0 {
			return
		}
		// Cost of n bytes in nanoseconds: n * 1e9 / bps
		costNano := (int64(n) * 1_000_000_000) / bps
		if costNano <= 0 {
			return
		}

		now := time.Now().UnixNano()
		minBase := now - burstWindowNano
		maxNext := now + maxQueueDelayNano

		prev := b.nextFreeNano.Load()
		base := prev
		if base < minBase {
			base = minBase
		}
		next := base + costNano
		// When concurrent streams fill the virtual queue past maxQueueDelayNano, wait
		// without reserving rather than clamping `next` (which would drop token debt
		// and allow bandwidth-limit bypass under high concurrency).
		if next > maxNext && base > now {
			wait := base - now
			if wait > sleepStepNano {
				wait = sleepStepNano
			}
			if wait < int64(2*time.Millisecond) {
				wait = int64(2 * time.Millisecond)
			}
			time.Sleep(time.Duration(wait))
			continue
		}
		if b.nextFreeNano.CompareAndSwap(prev, next) {
			targetNano = next
			break
		}
	}

	for {
		if b.rateBps.Load() <= 0 || b.epoch.Load() != startEpoch {
			return
		}
		rem := targetNano - time.Now().UnixNano()
		if rem <= int64(time.Millisecond) {
			return
		}
		if rem > sleepStepNano {
			time.Sleep(time.Duration(sleepStepNano))
			continue
		}
		time.Sleep(time.Duration(rem))
		return
	}
}

// Reader wraps an io.Reader with optional user and node lock-free rate limiting.
type Reader struct {
	R     io.Reader
	Limit *Bucket
	Node  *Bucket
}

func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.R.Read(p)
	if n > 0 {
		if r.Limit != nil {
			r.Limit.Wait(n)
		}
		if r.Node != nil {
			r.Node.Wait(n)
		}
	}
	return n, err
}
