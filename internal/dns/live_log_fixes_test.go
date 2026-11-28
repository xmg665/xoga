package dns

import (
	"context"
	"net"
	"net/netip"
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
