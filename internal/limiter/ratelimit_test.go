package limiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestN9HighConcurrencyDoesNotBypassRateLimit(t *testing.T) {
	// 100 KB/s limit with 40 concurrent goroutines each sending 10 KB chunks (400 KB total ->
	// must take ~3.5s..4.5s with 250ms burst; old 2s clamp bug finished in ~2.0s bypassing 2x!).
	b := NewBucketBps(100 * 1024)
	const workers = 40
	const chunkBytes = 10 * 1024

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Wait(chunkBytes)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// 400 KB at 100 KB/s minus 250ms burst = ~3.75s theoretical minimum.
	// Allow scheduling jitter down to 3.2s; old bug completed at ~2.0s!
	if elapsed < 3200*time.Millisecond {
		t.Fatalf("rate limit bypassed under high concurrency: 400KB @ 100KB/s finished in %v (expected >=3.2s)", elapsed)
	}
}

func TestRateLimitIncreaseWakesWaitersQuickly(t *testing.T) {
	b := NewBucketBps(10 * 1024) // 10 KB/s
	var done atomic.Bool
	go func() {
		b.Wait(40 * 1024) // would normally sleep ~3.75s
		done.Store(true)
	}()
	time.Sleep(50 * time.Millisecond)
	b.SetBytesPerSec(0) // remove limit
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if done.Load() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("Wait() did not wake quickly when rate limit was cleared")
}
