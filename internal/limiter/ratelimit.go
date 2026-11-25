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
	rateBps      atomic.Int64 // bytes per second; <= 0 means unlimited
	nextFreeNano atomic.Int64 // virtual scheduling timestamp (UnixNano)
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
		b.rateBps.Store(0)
		return
	}
	bps := int64(mbps * 125000.0)
	if bps < 1024 {
		bps = 1024
	}
	b.rateBps.Store(bps)
}

func (b *Bucket) SetBytesPerSec(bps int64) {
	if bps <= 0 {
		b.rateBps.Store(0)
		return
	}
	b.rateBps.Store(bps)
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
	bps := b.rateBps.Load()
	if bps <= 0 {
		return
	}

	// Cost of n bytes in nanoseconds: n * 1e9 / bps
	costNano := (int64(n) * 1_000_000_000) / bps
	// Allow up to 250ms burst window for smooth TCP congestion window ramp-up
	const burstWindowNano = int64(250 * time.Millisecond)

	now := time.Now().UnixNano()
	minBase := now - burstWindowNano

	var waitNano int64
	for {
		prev := b.nextFreeNano.Load()
		base := prev
		if base < minBase {
			base = minBase
		}
		next := base + costNano
		if b.nextFreeNano.CompareAndSwap(prev, next) {
			if next > now {
				waitNano = next - now
			}
			break
		}
	}

	if waitNano > int64(time.Millisecond) {
		time.Sleep(time.Duration(waitNano))
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
