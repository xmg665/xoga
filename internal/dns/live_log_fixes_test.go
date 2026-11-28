package dns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBUG1SystemDNSCacheSingleflightServeStaleNegativeCacheAndIPv4First(t *testing.T) {
	// 1. Empty default_dns & empty dns.yml routes through cache + singleflight + "ip4" first!
	t.Run("SingleflightCacheAndIPv4FirstNoAAAA", func(t *testing.T) {
		var ip4Calls atomic.Int32
		var ip6Calls atomic.Int32
		var otherCalls atomic.Int32

		res := NewResolver("", "", nil, "ipv4_first")
		res.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			switch network {
			case "ip4":
				ip4Calls.Add(1)
				time.Sleep(30 * time.Millisecond)
				return []netip.Addr{netip.MustParseAddr("142.250.190.46")}, nil
			case "ip6":
				ip6Calls.Add(1)
				return []netip.Addr{netip.MustParseAddr("2607:f8b0:4005:80b::200e")}, nil
			default:
				otherCalls.Add(1)
				return nil, &net.DNSError{Err: "unexpected network " + network, Name: host}
			}
		}

		// 32 concurrent lookups must coalesce into 1 "ip4" lookup with ZERO "ip6" or "ip" lookups!
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				addrs, err := res.ResolveAll(context.Background(), "www.google.com", 0, false)
				if err != nil || len(addrs) != 1 || addrs[0].String() != "142.250.190.46" {
					t.Errorf("unexpected resolve result: addrs=%v err=%v", addrs, err)
				}
			}()
		}
		wg.Wait()

		if got := ip4Calls.Load(); got != 1 {
			t.Fatalf("expected 1 singleflight ip4 system lookup across 32 callers, got %d", got)
		}
		if got := ip6Calls.Load(); got != 0 {
			t.Fatalf("expected 0 ip6 lookups when ip4 succeeded under ipv4_first, got %d", got)
		}
		if got := otherCalls.Load(); got != 0 {
			t.Fatalf("expected 0 dual-stack \"ip\" lookups under ipv4_first, got %d", got)
		}

		// Repeated calls hit positive cache (still 1 total lookup)
		for i := 0; i < 10; i++ {
			addrs, err := res.ResolveAll(context.Background(), "www.google.com", 0, false)
			if err != nil || len(addrs) != 1 || addrs[0].String() != "142.250.190.46" {
				t.Fatalf("cache hit failed: addrs=%v err=%v", addrs, err)
			}
		}
		if got := ip4Calls.Load(); got != 1 {
			t.Fatalf("expected positive cache hit on system DNS, got %d lookups", got)
		}

		// Expire positive entry and simulate system DNS SERVFAIL outage -> RFC 8767 serve-stale!
		res.cacheMu.Lock()
		for k, v := range res.cache {
			v.expires = time.Now().Unix() - 10
			res.cache[k] = v
		}
		res.cacheMu.Unlock()

		var failCalls atomic.Int32
		res.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			failCalls.Add(1)
			return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
		}

		// First lookup during outage triggers 1 refresh attempt (fails) and returns stale IP!
		stale, err := res.ResolveAll(context.Background(), "www.google.com", 0, false)
		if err != nil || len(stale) != 1 || stale[0].String() != "142.250.190.46" {
			t.Fatalf("expected RFC 8767 serve-stale IP on system DNS outage, got %v err=%v", stale, err)
		}
		// Immediate follow-up calls within negative backoff window keep serving stale WITHOUT hammering upstream!
		for i := 0; i < 20; i++ {
			stale2, err2 := res.ResolveAll(context.Background(), "www.google.com", 0, false)
			if err2 != nil || len(stale2) != 1 || stale2[0].String() != "142.250.190.46" {
				t.Fatalf("expected serve-stale during backoff, got %v err=%v", stale2, err2)
			}
		}
		if got := failCalls.Load(); got != 1 {
			t.Fatalf("expected only 1 refresh attempt during serve-stale backoff, got %d", got)
		}
	})

	// 2. IPv4First falls back to "ip6" ONLY when "ip4" has no A record (IsNotFound), NOT on SERVFAIL/timeout!
	t.Run("IPv4FirstFallbackOnlyOnEmptyOrNotFound", func(t *testing.T) {
		var ip4Calls, ip6Calls atomic.Int32
		res := NewResolver("", "", nil, "ipv4_first")
		res.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			if host == "v6only.example.test" {
				if network == "ip4" {
					ip4Calls.Add(1)
					return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
				}
				ip6Calls.Add(1)
				return []netip.Addr{netip.MustParseAddr("2001:db8::cafe")}, nil
			}
			// servfail.example.test -> SERVFAIL on ip4 must NOT waste a query on ip6!
			if network == "ip4" {
				ip4Calls.Add(1)
				return nil, &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}
			}
			ip6Calls.Add(1)
			return nil, &net.DNSError{Err: "should not be called", Name: host}
		}

		addrs, err := res.ResolveAll(context.Background(), "v6only.example.test", 0, false)
		if err != nil || len(addrs) != 1 || addrs[0].String() != "2001:db8::cafe" {
			t.Fatalf("expected IPv6 fallback for IPv6-only domain, got %v err=%v", addrs, err)
		}
		if ip4Calls.Load() != 1 || ip6Calls.Load() != 1 {
			t.Fatalf("expected 1 ip4 + 1 ip6 call for v6only, got ip4=%d ip6=%d", ip4Calls.Load(), ip6Calls.Load())
		}

		ip4Calls.Store(0)
		ip6Calls.Store(0)
		if _, err := res.ResolveAll(context.Background(), "servfail.example.test", 0, false); err == nil {
			t.Fatal("expected SERVFAIL error")
		}
		if ip4Calls.Load() != 1 || ip6Calls.Load() != 0 {
			t.Fatalf("SERVFAIL on ip4 must NOT fall back to ip6: got ip4=%d ip6=%d", ip4Calls.Load(), ip6Calls.Load())
		}
	})

	// 3. Negative caching coalesces and suppresses repeated NXDOMAIN storms (e.g. api.martianwallet.xyz 27,468x)
	t.Run("NegativeCacheSuppressesNXDOMAINStorm", func(t *testing.T) {
		var calls atomic.Int32
		res := NewResolver("", "", nil, "ipv4_first")
		res.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
			calls.Add(1)
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}

		for i := 0; i < 50; i++ {
			if _, err := res.ResolveAll(context.Background(), "api.martianwallet.xyz", 0, false); err == nil {
				t.Fatal("expected NXDOMAIN error")
			}
		}
		// 1 ip4 + 1 ip6 on first miss, then 49 negative cache hits (0 upstream lookups)!
		if got := calls.Load(); got != 2 {
			t.Fatalf("expected 2 initial lookups (ip4+ip6) then 49 negative cache hits, got %d calls", got)
		}
	})

	// 4. Negative cache flood must NEVER evict valid positive entries when cache is full!
	t.Run("NegativeFloodDoesNotEvictPositiveEntries", func(t *testing.T) {
		res := NewResolver("", "", nil, "ipv4_only")
		now := time.Now().Unix()
		res.cacheMu.Lock()
		for i := 0; i < maxCacheEntries; i++ {
			res.cache[cacheKey{
				domain:   "pos-" + string(rune('a'+(i%26))) + "-" + time.Duration(i).String(),
				server:   systemDNSServer,
				strategy: StrategyIPv4Only,
			}] = cacheEntry{
				addrs:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				expires: now + 600,
			}
		}
		res.cacheMu.Unlock()

		res.putNegativeCache(cacheKey{domain: "flood.nx", server: systemDNSServer, strategy: StrategyIPv4Only}, errDNSNXDomain, 15)

		res.cacheMu.RLock()
		posCount := 0
		for _, v := range res.cache {
			if len(v.addrs) > 0 {
				posCount++
			}
		}
		res.cacheMu.RUnlock()
		if posCount != maxCacheEntries {
			t.Fatalf("negative cache insert evicted positive entries: kept %d/%d", posCount, maxCacheEntries)
		}
	})
}

func TestNegativeCacheNotStarvedByFullPositiveCacheAndRecovery(t *testing.T) {
	dnsFile := filepath.Join(t.TempDir(), "dns.yml")
	if err := os.WriteFile(dnsFile, []byte("# empty\n"), 0644); err != nil {
		t.Fatal(err)
	}
	res := NewResolver(dnsFile, "", nil, "ipv4_only")

	var lookupCalls atomic.Int32
	var recoverHost atomic.Bool
	res.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookupCalls.Add(1)
		if host == "recover.example.test" && recoverHost.Load() {
			return []netip.Addr{netip.MustParseAddr("203.0.113.42")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	// 1. Fill positive cache completely with maxCacheEntries entries (half fresh, half expired within 30m serve-stale window).
	now := time.Now().Unix()
	res.cacheMu.Lock()
	for i := 0; i < maxCacheEntries; i++ {
		exp := now + 600
		if i%2 == 0 {
			exp = now - 60 // expired 1m ago (kept for serve-stale)
		}
		res.cache[cacheKey{
			domain:   "pos-" + strconv.Itoa(i) + ".example.test",
			server:   systemDNSServer,
			strategy: StrategyIPv4Only,
		}] = cacheEntry{
			addrs:   []netip.Addr{netip.MustParseAddr("198.51.100.1")},
			expires: exp,
		}
	}
	res.cacheMu.Unlock()

	// 2. Repeated NXDOMAIN lookups MUST still be negative-cached (1 upstream call, NOT 20)
	//    and MUST NOT evict any positive entries!
	for i := 0; i < 20; i++ {
		if _, err := res.ResolveAll(context.Background(), "storm.missing.test", 0, false); err == nil {
			t.Fatal("expected NXDOMAIN error")
		}
	}
	if got := lookupCalls.Load(); got != 1 {
		t.Fatalf("full positive cache starved negative cache: expected 1 upstream lookup, got %d", got)
	}
	res.cacheMu.RLock()
	posCount := len(res.cache)
	negCount := len(res.negCache)
	res.cacheMu.RUnlock()
	if posCount != maxCacheEntries {
		t.Fatalf("expected all %d positive entries preserved, got %d", maxCacheEntries, posCount)
	}
	if negCount != 1 {
		t.Fatalf("expected 1 negative cache entry, got %d", negCount)
	}

	// 3. Flooding negative cache beyond maxNegCacheEntries stays bounded and never evicts positive entries.
	for i := 0; i < maxNegCacheEntries+500; i++ {
		res.putNegativeCache(cacheKey{
			domain:   "nx-" + strconv.Itoa(i) + ".missing.test",
			server:   systemDNSServer,
			strategy: StrategyIPv4Only,
		}, errDNSNXDomain, 15)
	}
	res.cacheMu.RLock()
	posAfterFlood := len(res.cache)
	negAfterFlood := len(res.negCache)
	res.cacheMu.RUnlock()
	if posAfterFlood != maxCacheEntries {
		t.Fatalf("negative flood evicted positive entries: kept %d/%d", posAfterFlood, maxCacheEntries)
	}
	if negAfterFlood > maxNegCacheEntries {
		t.Fatalf("negative cache exceeded bound: %d > %d", negAfterFlood, maxNegCacheEntries)
	}

	// 4. Positive cache insert when full evicts expired stale entries before fresh TTL-valid ones.
	res.putCache(cacheKey{domain: "fresh-new.example.test", server: systemDNSServer, strategy: StrategyIPv4Only}, []netip.Addr{netip.MustParseAddr("198.51.100.9")}, 300)
	res.cacheMu.RLock()
	freshKept := 0
	for k, v := range res.cache {
		if k.domain != "fresh-new.example.test" && v.expires > now {
			freshKept++
		}
	}
	res.cacheMu.RUnlock()
	if freshKept != maxCacheEntries/2 {
		t.Fatalf("putCache evicted fresh entries instead of expired serve-stale entries: kept %d/%d fresh", freshKept, maxCacheEntries/2)
	}

	// 5. Recovery: putCache deletes any stale negCache entry for the same key.
	ckRec := cacheKey{domain: "recover.example.test", server: systemDNSServer, strategy: StrategyIPv4Only}
	res.putNegativeCache(ckRec, errDNSNXDomain, 60)
	recoverHost.Store(true)
	res.putCache(ckRec, []netip.Addr{netip.MustParseAddr("203.0.113.42")}, 120)
	addrs, err := res.ResolveAll(context.Background(), "recover.example.test", 0, false)
	if err != nil || len(addrs) != 1 || addrs[0].String() != "203.0.113.42" {
		t.Fatalf("recovered domain should resolve from positive cache, got addrs=%v err=%v", addrs, err)
	}

	// 6. Hot-reload of dns.yml clears BOTH positive and negative caches.
	future := time.Now().Add(10 * time.Second)
	if err := os.WriteFile(dnsFile, []byte("# updated\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(dnsFile, future, future)
	res.reloadNow(false)
	res.cacheMu.RLock()
	posAfterReload := len(res.cache)
	negAfterReload := len(res.negCache)
	res.cacheMu.RUnlock()
	if posAfterReload != 0 || negAfterReload != 0 {
		t.Fatalf("reloadNow must clear both caches, got pos=%d neg=%d", posAfterReload, negAfterReload)
	}

	// 7. Negative cache TTL expiry -> next ResolveAll retries upstream and recovers cleanly!
	var retryCount atomic.Int32
	var allowResolve atomic.Bool
	resExp := NewResolver("", "", nil, "ipv4_only")
	resExp.systemLookup = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		retryCount.Add(1)
		if allowResolve.Load() {
			return []netip.Addr{netip.MustParseAddr("198.51.100.88")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if _, err := resExp.ResolveAll(context.Background(), "ttl-recover.example.test", 0, false); err == nil {
		t.Fatal("expected initial NXDOMAIN")
	}
	// Backdate negCache expiry so TTL has elapsed
	resExp.cacheMu.Lock()
	for k, v := range resExp.negCache {
		v.expires = time.Now().Unix() - 1
		resExp.negCache[k] = v
	}
	resExp.cacheMu.Unlock()
	allowResolve.Store(true)
	addrsExp, err := resExp.ResolveAll(context.Background(), "ttl-recover.example.test", 0, false)
	if err != nil || len(addrsExp) != 1 || addrsExp[0].String() != "198.51.100.88" {
		t.Fatalf("expected recovery after negative cache expiry, got %v err=%v", addrsExp, err)
	}
	if retryCount.Load() != 2 {
		t.Fatalf("expected exactly 2 system lookups (initial fail + post-expiry recovery), got %d", retryCount.Load())
	}

	// 8. Real net.DefaultResolver.LookupNetIP path (systemLookup == nil) resolves localhost under ipv4_first!
	realRes := NewResolver("", "", nil, "ipv4_first")
	localAddrs, err := realRes.ResolveAll(context.Background(), "localhost", 0, false)
	if err != nil || len(localAddrs) == 0 || !localAddrs[0].Is4() || !localAddrs[0].IsLoopback() {
		t.Fatalf("real system resolver ipv4_first localhost lookup failed: addrs=%v err=%v", localAddrs, err)
	}
}
