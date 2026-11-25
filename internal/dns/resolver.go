package dns

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/bufpool"
	"github.com/xmg665/xoga/internal/logger"
)

type Strategy uint8

const (
	StrategyIPv4First Strategy = iota
	StrategyIPv6First
	StrategyIPv4Only
	StrategyIPv6Only
)

func ParseStrategy(s string) Strategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ipv4_only", "ipv4", "v4_only", "use_ipv4":
		return StrategyIPv4Only
	case "ipv6_only", "ipv6", "v6_only", "use_ipv6":
		return StrategyIPv6Only
	case "ipv6_first", "prefer_ipv6":
		return StrategyIPv6First
	default:
		return StrategyIPv4First
	}
}

func (s Strategy) String() string {
	switch s {
	case StrategyIPv4Only:
		return "ipv4_only"
	case StrategyIPv6Only:
		return "ipv6_only"
	case StrategyIPv6First:
		return "ipv6_first"
	default:
		return "ipv4_first"
	}
}

const (
	qTypeA    uint16 = 1
	qTypeAAAA uint16 = 28
	maxCacheEntries  = 4096
)

type upstreamRule struct {
	server    string // e.g. "154.12.1.1:53", "tcp://8.8.8.8:53", "https://dns.example.com/dns-query"
	strategy  Strategy
	isCatch   bool // true when server has no rules or `else` wildcard
	exact     map[string]struct{}
	suffixMap map[string]struct{}
	keywords  []string
	regexps   []*regexp.Regexp
}

func (u *upstreamRule) matches(domain string) bool {
	if u.isCatch {
		return true
	}
	if _, ok := u.exact[domain]; ok {
		return true
	}
	if len(u.suffixMap) > 0 {
		for cur := domain; ; {
			if _, ok := u.suffixMap[cur]; ok {
				return true
			}
			dot := strings.IndexByte(cur, '.')
			if dot < 0 {
				break
			}
			cur = cur[dot+1:]
		}
	}
	for _, kw := range u.keywords {
		if strings.Contains(domain, kw) {
			return true
		}
	}
	for _, re := range u.regexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}

func (u *upstreamRule) addPattern(raw string) {
	p := strings.TrimSpace(raw)
	if p == "" || strings.HasPrefix(p, "#") {
		return
	}
	if p == "*" || strings.EqualFold(p, "all") || strings.EqualFold(p, "default") || strings.EqualFold(p, "else") {
		u.isCatch = true
		return
	}
	if expanded, ok := acl.ExpandGeosite(p); ok {
		for _, sub := range expanded {
			u.addPattern(sub)
		}
		return
	}
	if strings.HasPrefix(p, "full:") {
		u.exact[strings.ToLower(strings.TrimSpace(p[5:]))] = struct{}{}
		return
	}
	if strings.HasPrefix(p, "domain:") {
		p = strings.TrimSpace(p[7:])
	} else if strings.HasPrefix(p, "keyword:") {
		kw := strings.ToLower(strings.TrimSpace(p[8:]))
		if kw != "" {
			u.keywords = append(u.keywords, kw)
		}
		return
	} else if strings.HasPrefix(p, "regexp:") {
		if re, err := regexp.Compile(strings.TrimSpace(p[7:])); err == nil {
			u.regexps = append(u.regexps, re)
		}
		return
	}
	s := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(p, "*."), "."))
	if s != "" {
		if u.suffixMap == nil {
			u.suffixMap = make(map[string]struct{})
		}
		u.suffixMap[s] = struct{}{}
	}
}

type dnsSnapshot struct {
	rules           []upstreamRule
	defaultServers  []string
	defaultStrategy Strategy
}

type cacheKey struct {
	domain   string
	server   string
	strategy Strategy
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires int64 // Unix seconds
}

type inflightCall struct {
	done  chan struct{}
	addrs []netip.Addr
	ttl   uint32
	err   error
}

// Resolver provides rule-based DNS unlocking (UDP, TCP, and RFC 8484 DoH), IPv4/IPv6 strategy
// selection, singleflight query coalescing, RFC 8767 serve-stale fallback, bounded TTL caching,
// and automatic hot-reloading of `/etc/xoga/dns.yml`.
type Resolver struct {
	configPath      string
	remoteURL       string
	defaultServers  []string
	defaultStrategy Strategy
	maxTTLSec       atomic.Int64

	snap atomic.Pointer[dnsSnapshot]

	reloadMu  sync.Mutex
	lastMtime time.Time
	lastCheck atomic.Int64

	cacheMu sync.RWMutex
	cache   map[cacheKey]cacheEntry

	inflightMu sync.Mutex
	inflight   map[cacheKey]*inflightCall

	dohClient *http.Client
}

func NewResolver(dnsYmlPath, dnsConfigURL string, defaultServers []string, defaultStrategy string) *Resolver {
	r := &Resolver{
		configPath:      dnsYmlPath,
		remoteURL:       strings.TrimSpace(dnsConfigURL),
		defaultServers:  normalizeServerList(defaultServers),
		defaultStrategy: ParseStrategy(defaultStrategy),
		cache:           make(map[cacheKey]cacheEntry, 256),
		inflight:        make(map[cacheKey]*inflightCall, 32),
		dohClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
	r.maxTTLSec.Store(600)
	r.reloadNow(true)
	return r
}

// SetCacheMinutes configures the maximum DNS cache TTL in minutes (`dns_cache_time` in soga.conf).
func (r *Resolver) SetCacheMinutes(minutes int) {
	if r != nil && minutes > 0 {
		r.maxTTLSec.Store(int64(minutes) * 60)
	}
}

// HasRuleForDomain reports whether `dns.yml` has an explicit rule matching domain
// (used when `domain_sniff` overrides destination IP with sniffed TLS SNI / HTTP Host).
func (r *Resolver) HasRuleForDomain(domain string) bool {
	if r == nil || domain == "" {
		return false
	}
	r.maybeHotReload()
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	sn := r.snap.Load()
	if sn == nil {
		return false
	}
	for i := range sn.rules {
		if !sn.rules[i].isCatch && sn.rules[i].matches(d) {
			return true
		}
	}
	return false
}

// Resolve resolves host (or returns literal IP directly) according to `dns.yml`, `default_dns`,
// and an optional per-route strategy override.
func (r *Resolver) Resolve(ctx context.Context, host string, overrideStrategy Strategy, hasOverride bool) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if hasOverride {
			if overrideStrategy == StrategyIPv4Only && !ip.Is4() {
				return netip.Addr{}, errors.New("ipv4_only strategy rejected IPv6 literal")
			}
			if overrideStrategy == StrategyIPv6Only && !ip.Is6() {
				return netip.Addr{}, errors.New("ipv6_only strategy rejected IPv4 literal")
			}
		}
		return ip, nil
	}

	if r == nil {
		return fallbackSystemResolve(ctx, host, overrideStrategy, hasOverride)
	}

	r.maybeHotReload()
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	sn := r.snap.Load()

	var servers []string
	strat := r.defaultStrategy

	if sn != nil {
		for i := range sn.rules {
			if sn.rules[i].matches(domain) {
				servers = []string{sn.rules[i].server}
				strat = sn.rules[i].strategy
				break
			}
		}
		if len(servers) == 0 && len(sn.defaultServers) > 0 {
			servers = sn.defaultServers
		}
	}
	if hasOverride {
		strat = overrideStrategy
	}

	// If no custom DNS server matched and default_dns is empty, use Go system resolver with strategy filter
	if len(servers) == 0 {
		return fallbackSystemResolve(ctx, domain, strat, true)
	}

	ck := cacheKey{domain: domain, server: servers[0], strategy: strat}
	now := time.Now().Unix()

	var staleAddr netip.Addr
	r.cacheMu.RLock()
	if ce, ok := r.cache[ck]; ok && len(ce.addrs) > 0 {
		if ce.expires > now {
			addr := ce.addrs[0]
			r.cacheMu.RUnlock()
			return addr, nil
		}
		// Keep recently expired IP (up to 30m) for RFC 8767 serve-stale fallback on upstream timeout
		if now-ce.expires <= 1800 {
			staleAddr = ce.addrs[0]
		}
	}
	r.cacheMu.RUnlock()

	// Coalesce concurrent identical lookups via zero-dependency singleflight
	r.inflightMu.Lock()
	if call, dup := r.inflight[ck]; dup {
		r.inflightMu.Unlock()
		select {
		case <-call.done:
			if call.err == nil && len(call.addrs) > 0 {
				return call.addrs[0], nil
			}
			if staleAddr.IsValid() {
				return staleAddr, nil
			}
			return netip.Addr{}, call.err
		case <-ctx.Done():
			if staleAddr.IsValid() {
				return staleAddr, nil
			}
			return netip.Addr{}, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	r.inflight[ck] = call
	r.inflightMu.Unlock()

	var addrs []netip.Addr
	var ttl uint32
	var lastErr error
	for _, srv := range servers {
		addrs, ttl, lastErr = r.queryServerWithStrategy(ctx, srv, domain, strat)
		if lastErr == nil && len(addrs) > 0 {
			r.putCache(ck, addrs, ttl)
			break
		}
	}
	if lastErr == nil && len(addrs) == 0 {
		lastErr = fmt.Errorf("no DNS answer for %s", domain)
	} else if lastErr != nil {
		lastErr = fmt.Errorf("dns resolve %s via %v: %w", domain, servers, lastErr)
	}

	call.addrs = addrs
	call.ttl = ttl
	call.err = lastErr
	close(call.done)

	r.inflightMu.Lock()
	delete(r.inflight, ck)
	r.inflightMu.Unlock()

	if lastErr == nil && len(addrs) > 0 {
		return addrs[0], nil
	}
	if staleAddr.IsValid() {
		return staleAddr, nil
	}
	return netip.Addr{}, lastErr
}

func (r *Resolver) putCache(ck cacheKey, addrs []netip.Addr, ttl uint32) {
	maxSec := r.maxTTLSec.Load()
	if maxSec <= 0 {
		maxSec = 600
	}
	ttlSec := int64(ttl)
	if ttlSec < 30 {
		ttlSec = 30
	} else if ttlSec > maxSec {
		ttlSec = maxSec
	}
	exp := time.Now().Unix() + ttlSec

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if len(r.cache) >= maxCacheEntries {
		now := time.Now().Unix()
		for k, v := range r.cache {
			if v.expires <= now {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxCacheEntries {
			// Evict ~25% entries to keep map bounded with zero allocation spikes
			n := 0
			for k := range r.cache {
				delete(r.cache, k)
				n++
				if n >= maxCacheEntries/4 {
					break
				}
			}
		}
	}
	r.cache[ck] = cacheEntry{addrs: addrs, expires: exp}
}

func (r *Resolver) queryServerWithStrategy(ctx context.Context, srv, domain string, strat Strategy) ([]netip.Addr, uint32, error) {
	switch strat {
	case StrategyIPv4Only:
		return r.querySingleType(ctx, srv, domain, qTypeA)
	case StrategyIPv6Only:
		return r.querySingleType(ctx, srv, domain, qTypeAAAA)
	case StrategyIPv6First:
		if a6, ttl, err := r.querySingleType(ctx, srv, domain, qTypeAAAA); err == nil && len(a6) > 0 {
			return a6, ttl, nil
		}
		return r.querySingleType(ctx, srv, domain, qTypeA)
	default: // StrategyIPv4First
		if a4, ttl, err := r.querySingleType(ctx, srv, domain, qTypeA); err == nil && len(a4) > 0 {
			return a4, ttl, nil
		}
		return r.querySingleType(ctx, srv, domain, qTypeAAAA)
	}
}

func (r *Resolver) querySingleType(ctx context.Context, srv, domain string, qtype uint16) ([]netip.Addr, uint32, error) {
	reqWire, txID, err := encodeDNSQuery(domain, qtype)
	if err != nil {
		return nil, 0, err
	}

	var respWire []byte
	lower := strings.ToLower(srv)
	switch {
	case strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://"):
		respWire, err = r.exchangeDoH(ctx, srv, reqWire)
	case strings.HasPrefix(lower, "tcp://"):
		respWire, err = exchangeTCP(ctx, ensurePort53(srv[6:]), reqWire)
	case strings.HasPrefix(lower, "udp://"):
		respWire, err = exchangeUDP(ctx, ensurePort53(srv[6:]), reqWire)
	default:
		respWire, err = exchangeUDP(ctx, ensurePort53(srv), reqWire)
	}
	if err != nil {
		return nil, 0, err
	}
	return decodeDNSAnswers(respWire, txID, qtype)
}

func (r *Resolver) exchangeDoH(ctx context.Context, dohURL string, wire []byte) ([]byte, error) {
	// Per RFC 8484, DoH requests set DNS ID to 0 for HTTP cache friendliness (we accept original or 0)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8192))
}

func exchangeUDP(ctx context.Context, addr string, wire []byte) ([]byte, error) {
	var d net.Dialer
	d.Timeout = 3 * time.Second
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	bp := bufpool.Get(bufpool.SmallSize)
	defer bufpool.Put(bp)
	n, err := conn.Read(*bp)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, (*bp)[:n])
	return out, nil
}

func exchangeTCP(ctx context.Context, addr string, wire []byte) ([]byte, error) {
	var d net.Dialer
	d.Timeout = 4 * time.Second
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var lenHdr [2]byte
	binary.BigEndian.PutUint16(lenHdr[:], uint16(len(wire)))
	bufs := net.Buffers{lenHdr[:], wire}
	if _, err := bufs.WriteTo(conn); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenHdr[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if respLen <= 12 || respLen > 16384 {
		return nil, errors.New("invalid TCP DNS response length")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// encodeDNSQuery constructs an RFC 1035 standard recursive query packet.
func encodeDNSQuery(domain string, qtype uint16) ([]byte, uint16, error) {
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	txID := binary.BigEndian.Uint16(idBytes[:])

	buf := make([]byte, 12, 128)
	binary.BigEndian.PutUint16(buf[0:2], txID)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD=1 (Recursion Desired)
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1

	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, lb := range labels {
		if len(lb) == 0 || len(lb) > 63 {
			return nil, 0, fmt.Errorf("invalid domain label %q", lb)
		}
		buf = append(buf, byte(len(lb)))
		buf = append(buf, lb...)
	}
	buf = append(buf, 0x00) // root label
	var qtail [4]byte
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // QCLASS=IN
	buf = append(buf, qtail[:]...)
	return buf, txID, nil
}

func decodeDNSAnswers(msg []byte, expectedID uint16, qtype uint16) ([]netip.Addr, uint32, error) {
	if len(msg) < 12 {
		return nil, 0, errors.New("short DNS packet")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if id != expectedID && id != 0 {
		return nil, 0, errors.New("DNS transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, 0, fmt.Errorf("DNS rcode=%d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	pos := 12
	for i := 0; i < qdCount; i++ {
		next, err := skipDNSName(msg, pos)
		if err != nil || next+4 > len(msg) {
			return nil, 0, errors.New("malformed DNS question")
		}
		pos = next + 4
	}

	var addrs []netip.Addr
	var minTTL uint32 = 300
	for i := 0; i < anCount; i++ {
		next, err := skipDNSName(msg, pos)
		if err != nil || next+10 > len(msg) {
			break
		}
		pos = next
		rrType := binary.BigEndian.Uint16(msg[pos : pos+2])
		ttl := binary.BigEndian.Uint32(msg[pos+4 : pos+8])
		rdLen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdLen > len(msg) {
			break
		}
		rdata := msg[pos : pos+rdLen]
		pos += rdLen

		if rrType == qtype {
			if qtype == qTypeA && rdLen == 4 {
				var a4 [4]byte
				copy(a4[:], rdata)
				addrs = append(addrs, netip.AddrFrom4(a4))
				if ttl < minTTL {
					minTTL = ttl
				}
			} else if qtype == qTypeAAAA && rdLen == 16 {
				var a16 [16]byte
				copy(a16[:], rdata)
				addrs = append(addrs, netip.AddrFrom16(a16))
				if ttl < minTTL {
					minTTL = ttl
				}
			}
		}
	}
	return addrs, minTTL, nil
}

func skipDNSName(msg []byte, pos int) (int, error) {
	jumps := 0
	for pos < len(msg) {
		b := msg[pos]
		if b == 0 {
			return pos + 1, nil
		}
		if (b & 0xC0) == 0xC0 { // compression pointer
			if pos+1 >= len(msg) {
				return 0, errors.New("truncated pointer")
			}
			return pos + 2, nil
		}
		pos += 1 + int(b)
		jumps++
		if jumps > 64 {
			return 0, errors.New("name too long")
		}
	}
	return 0, errors.New("unterminated DNS name")
}

func fallbackSystemResolve(ctx context.Context, host string, strat Strategy, filter bool) (netip.Addr, error) {
	network := "ip"
	if filter {
		switch strat {
		case StrategyIPv4Only:
			network = "ip4"
		case StrategyIPv6Only:
			network = "ip6"
		}
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, host)
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = fmt.Errorf("no IP found for %s", host)
		}
		return netip.Addr{}, err
	}
	if filter {
		if strat == StrategyIPv4First {
			for _, ip := range ips {
				if ip.Unmap().Is4() {
					return ip.Unmap(), nil
				}
			}
		} else if strat == StrategyIPv6First {
			for _, ip := range ips {
				if ip.Unmap().Is6() {
					return ip.Unmap(), nil
				}
			}
		}
	}
	return ips[0].Unmap(), nil
}

// maybeHotReload checks `/etc/xoga/dns.yml` mtime at most once every 5 seconds and hot-swaps rules!
func (r *Resolver) maybeHotReload() {
	now := time.Now().Unix()
	prev := r.lastCheck.Load()
	if now-prev < 5 || !r.lastCheck.CompareAndSwap(prev, now) {
		return
	}
	r.reloadNow(false)
}

func (r *Resolver) reloadNow(initial bool) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	var raw []byte
	if r.remoteURL != "" && initial {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.remoteURL, nil)
		if err == nil {
			if resp, derr := r.dohClient.Do(req); derr == nil {
				raw, _ = io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
				_ = resp.Body.Close()
			}
		}
		cancel()
	}

	if len(raw) == 0 && r.configPath != "" {
		st, err := os.Stat(r.configPath)
		if err != nil {
			if initial {
				r.snap.Store(&dnsSnapshot{
					defaultServers:  r.defaultServers,
					defaultStrategy: r.defaultStrategy,
				})
			}
			return
		}
		if !initial && st.ModTime().Equal(r.lastMtime) {
			return
		}
		data, err := os.ReadFile(r.configPath)
		if err != nil {
			return
		}
		r.lastMtime = st.ModTime()
		raw = data
	}

	rules, extraDefaults := ParseDNSYAML(string(raw), r.defaultStrategy)
	defs := append([]string(nil), r.defaultServers...)
	if len(defs) == 0 && len(extraDefaults) > 0 {
		defs = extraDefaults
	}

	r.snap.Store(&dnsSnapshot{
		rules:           rules,
		defaultServers:  defs,
		defaultStrategy: r.defaultStrategy,
	})

	// Clear cached answers on reload so newly edited DNS unlock IPs apply immediately
	r.cacheMu.Lock()
	clear(r.cache)
	r.cacheMu.Unlock()

	if !initial && len(rules) > 0 {
		logger.Infof("Hot-reloaded dns.yml (%d upstream rule groups, default_dns=%v)", len(rules), defs)
	}
}

// ParseDNSYAML parses soga-style `dns.yml` (both top-level server keys like
// `https://.../dns-query:` or `154.x.x.x:` with `strategy:` + `rules:` AND `servers:` list)
// without requiring a heavy external YAML reflection library.
func ParseDNSYAML(content string, defStrat Strategy) ([]upstreamRule, []string) {
	var rules []upstreamRule
	var defaultServers []string

	var cur *upstreamRule
	inServersList := false
	inRulesList := false

	flush := func() {
		if cur != nil && cur.server != "" {
			if len(cur.exact) == 0 && len(cur.suffixMap) == 0 && len(cur.keywords) == 0 && len(cur.regexps) == 0 {
				cur.isCatch = true
			}
			rules = append(rules, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		rawLine := sc.Text()
		// Strip trailing `#` comment outside URLs
		line := stripYAMLComment(rawLine)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "---" {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Top-level key (indent == 0)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			key := strings.TrimSpace(strings.TrimSuffix(trimmed, ":"))
			key = strings.Trim(key, "\"'")
			flush()
			inRulesList = false
			if strings.EqualFold(key, "servers") || strings.EqualFold(key, "nameservers") || strings.EqualFold(key, "default") {
				inServersList = true
				continue
			}
			inServersList = false
			cur = &upstreamRule{
				server:   key,
				strategy: defStrat,
				exact:    make(map[string]struct{}),
			}
			continue
		}

		if inServersList && strings.HasPrefix(trimmed, "-") {
			srv := strings.Trim(strings.TrimSpace(trimmed[1:]), "\"'")
			if srv != "" {
				defaultServers = append(defaultServers, srv)
			}
			continue
		}

		if cur == nil {
			continue
		}

		if strings.HasPrefix(trimmed, "-") && inRulesList {
			pat := strings.Trim(strings.TrimSpace(trimmed[1:]), "\"'")
			cur.addPattern(pat)
			continue
		}

		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), "\"'")
		switch k {
		case "strategy":
			cur.strategy = ParseStrategy(v)
			inRulesList = false
		case "rules", "domains", "match":
			inRulesList = true
			if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
				for _, item := range strings.Split(v[1:len(v)-1], ",") {
					cur.addPattern(strings.Trim(strings.TrimSpace(item), "\"'"))
				}
			}
		}
	}
	flush()
	return rules, normalizeServerList(defaultServers)
}

func stripYAMLComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

func ensurePort53(addr string) string {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

func normalizeServerList(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
