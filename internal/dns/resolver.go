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
	qTypeA          uint16 = 1
	qTypeAAAA       uint16 = 28
	maxCacheEntries        = 4096
)

type upstreamRule struct {
	server      string // e.g. "154.12.1.1:53", "tcp://8.8.8.8:53", "tls://1.1.1.1:853", "https://dns.example.com/dns-query"
	strategy    Strategy
	isCatch     bool // true when server has no rules key or `else` wildcard
	sawRulesKey bool
	exact       map[string]struct{}
	suffixMap   map[string]struct{}
	keywords    []string
	regexps     []*regexp.Regexp
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
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "geosite:") {
		return
	}
	if strings.HasPrefix(lower, "full:") {
		d := strings.TrimSuffix(strings.TrimSpace(lower[5:]), ".")
		if d != "" {
			u.exact[d] = struct{}{}
		}
		return
	}
	if strings.HasPrefix(lower, "domain:") {
		p = strings.TrimSpace(lower[7:])
	} else if strings.HasPrefix(lower, "keyword:") {
		kw := strings.TrimSpace(lower[8:])
		if kw != "" {
			u.keywords = append(u.keywords, kw)
		}
		return
	} else if strings.HasPrefix(lower, "regexp:") {
		expr := strings.TrimSpace(p[7:])
		if expr != "" && !strings.HasPrefix(expr, "(?i)") {
			expr = "(?i)" + expr
		}
		if re, err := regexp.Compile(expr); err == nil {
			u.regexps = append(u.regexps, re)
		}
		return
	}
	s := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "*."), "."), "."))
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
			// Do NOT set a hard Client.Timeout here because reloadNow(true) uses an 8s
			// context timeout for remote dns_config_url while exchangeDoH enforces a 5s
			// per-query context timeout.
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
	r.lastCheck.Store(time.Now().Unix())
	return r
}

// DefaultStrategy returns the resolver's configured default IPv4/IPv6 preference.
func (r *Resolver) DefaultStrategy() Strategy {
	if r == nil {
		return StrategyIPv4First
	}
	return r.defaultStrategy
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
	addrs, err := r.ResolveAll(ctx, host, overrideStrategy, hasOverride)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = fmt.Errorf("no IP found for %s", host)
		}
		return netip.Addr{}, err
	}
	return addrs[0], nil
}

// ResolveAll returns all candidate IPs for host ordered by strategy so outbound dialers can fail over across CDN IPs / dual-stack.
func (r *Resolver) ResolveAll(ctx context.Context, host string, overrideStrategy Strategy, hasOverride bool) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if hasOverride {
			if overrideStrategy == StrategyIPv4Only && !ip.Is4() {
				return nil, errors.New("ipv4_only strategy rejected IPv6 literal")
			}
			if overrideStrategy == StrategyIPv6Only && !ip.Is6() {
				return nil, errors.New("ipv6_only strategy rejected IPv4 literal")
			}
		}
		return []netip.Addr{ip}, nil
	}

	if r == nil {
		return fallbackSystemResolveAll(ctx, host, overrideStrategy, hasOverride)
	}

	r.maybeHotReload()
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	sn := r.snap.Load()

	var servers []string
	strat := r.defaultStrategy

	if sn != nil {
		// Pass 1: evaluate explicit domain rules first so catch-all servers listed earlier
		// in `servers:` (e.g. `- address: 1.1.1.1`) never shadow specific unlock rules.
		for i := range sn.rules {
			if !sn.rules[i].isCatch && sn.rules[i].matches(domain) {
				servers = []string{sn.rules[i].server}
				strat = sn.rules[i].strategy
				break
			}
		}
		// Pass 2: fall back to catch-all rules (preserving strategy of the first catch-all
		// and collecting all catch-all servers for failover).
		if len(servers) == 0 {
			for i := range sn.rules {
				if sn.rules[i].isCatch {
					if len(servers) == 0 {
						strat = sn.rules[i].strategy
					}
					servers = append(servers, sn.rules[i].server)
				}
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
		return fallbackSystemResolveAll(ctx, domain, strat, true)
	}

	ck := cacheKey{domain: domain, server: servers[0], strategy: strat}
	now := time.Now().Unix()

	var staleAddrs []netip.Addr
	r.cacheMu.RLock()
	if ce, ok := r.cache[ck]; ok && len(ce.addrs) > 0 {
		if ce.expires > now {
			addrs := ce.addrs
			r.cacheMu.RUnlock()
			return addrs, nil
		}
		// Keep recently expired IPs (up to 30m) for RFC 8767 serve-stale fallback on upstream timeout
		if now-ce.expires <= 1800 {
			staleAddrs = ce.addrs
		}
	}
	r.cacheMu.RUnlock()

	// Coalesce concurrent identical lookups via context-isolated singleflight so a single impatient
	// caller disconnecting never cancels the upstream lookup for sibling callers!
	r.inflightMu.Lock()
	call, dup := r.inflight[ck]
	if !dup {
		call = &inflightCall{done: make(chan struct{})}
		r.inflight[ck] = call
		go func(srvs []string) {
			perSrv := 5 * time.Second
			totalBudget := 5 * time.Second
			if len(srvs) > 1 {
				perSrv = 3 * time.Second
				if len(srvs) > 2 {
					perSrv = 2500 * time.Millisecond
				}
				totalBudget = time.Duration(len(srvs)) * perSrv
				if totalBudget > 10*time.Second {
					totalBudget = 10 * time.Second
				}
			}
			sfCtx, sfCancel := context.WithTimeout(context.Background(), totalBudget)
			defer sfCancel()

			var addrs []netip.Addr
			var ttl uint32
			var lastErr error
			for _, srv := range srvs {
				srvCtx, srvCancel := context.WithTimeout(sfCtx, perSrv)
				addrs, ttl, lastErr = r.queryServerWithStrategy(srvCtx, srv, domain, strat)
				srvCancel()
				if lastErr == nil && len(addrs) > 0 {
					r.putCache(ck, addrs, ttl)
					break
				}
			}
			if lastErr == nil && len(addrs) == 0 {
				lastErr = fmt.Errorf("no DNS answer for %s", domain)
			} else if lastErr != nil {
				lastErr = fmt.Errorf("dns resolve %s via %v: %w", domain, srvs, lastErr)
			}

			call.addrs = addrs
			call.ttl = ttl
			call.err = lastErr
			close(call.done)

			r.inflightMu.Lock()
			delete(r.inflight, ck)
			r.inflightMu.Unlock()
		}(servers)
	}
	r.inflightMu.Unlock()

	select {
	case <-call.done:
		if call.err == nil && len(call.addrs) > 0 {
			return call.addrs, nil
		}
		if len(staleAddrs) > 0 {
			return staleAddrs, nil
		}
		return nil, call.err
	case <-ctx.Done():
		if len(staleAddrs) > 0 {
			return staleAddrs, nil
		}
		return nil, ctx.Err()
	}
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

var errDNSNXDomain = errors.New("DNS rcode=3 (NXDOMAIN)")
var errDNSTruncated = errors.New("DNS response truncated (TC=1)")

func (r *Resolver) queryServerWithStrategy(ctx context.Context, srv, domain string, strat Strategy) ([]netip.Addr, uint32, error) {
	switch strat {
	case StrategyIPv4Only:
		return r.querySingleType(ctx, srv, domain, qTypeA)
	case StrategyIPv6Only:
		return r.querySingleType(ctx, srv, domain, qTypeAAAA)
	case StrategyIPv6First:
		a6, ttl, err := r.querySingleType(ctx, srv, domain, qTypeAAAA)
		if err == nil && len(a6) > 0 {
			return a6, ttl, nil
		}
		if errors.Is(err, errDNSNXDomain) || ctx.Err() != nil {
			return nil, 0, err
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, 0, err
		}
		return r.querySingleType(ctx, srv, domain, qTypeA)
	default: // StrategyIPv4First
		a4, ttl, err := r.querySingleType(ctx, srv, domain, qTypeA)
		if err == nil && len(a4) > 0 {
			return a4, ttl, nil
		}
		if errors.Is(err, errDNSNXDomain) || ctx.Err() != nil {
			return nil, 0, err
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, 0, err
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
	allowZeroID := false
	isUDP := false
	udpTarget := ""
	lower := strings.ToLower(srv)
	switch {
	case strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://"):
		allowZeroID = true
		respWire, err = r.exchangeDoH(ctx, srv, reqWire)
	case strings.HasPrefix(lower, "tls://"):
		respWire, err = exchangeDoT(ctx, srv[6:], reqWire)
	case strings.HasPrefix(lower, "tcp://"):
		respWire, err = exchangeTCP(ctx, ensurePort53(srv[6:]), reqWire)
	case strings.HasPrefix(lower, "udp://"):
		isUDP = true
		udpTarget = ensurePort53(srv[6:])
		respWire, err = exchangeUDP(ctx, udpTarget, reqWire)
	default:
		isUDP = true
		udpTarget = ensurePort53(srv)
		respWire, err = exchangeUDP(ctx, udpTarget, reqWire)
	}
	if err != nil {
		return nil, 0, err
	}
	addrs, ttl, decErr := decodeDNSAnswersForDomain(respWire, txID, domain, qtype, allowZeroID)
	if isUDP && errors.Is(decErr, errDNSTruncated) {
		// RFC 1035 TC=1 fallback over TCP when large CNAME chains truncate 512-byte UDP packet
		if tcpWire, terr := exchangeTCP(ctx, udpTarget, reqWire); terr == nil {
			return decodeDNSAnswersForDomain(tcpWire, txID, domain, qtype, false)
		}
	}
	return addrs, ttl, decErr
}

func (r *Resolver) exchangeDoH(ctx context.Context, dohURL string, wire []byte) ([]byte, error) {
	// Per RFC 8484, DoH requests set DNS ID to 0 for HTTP cache friendliness (we accept original or 0)
	dohCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(dohCtx, http.MethodPost, dohURL, bytes.NewReader(wire))
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
	if respLen < 12 || respLen > 16384 {
		return nil, errors.New("invalid TCP DNS response length")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func exchangeDoT(ctx context.Context, rawHost string, wire []byte) ([]byte, error) {
	rawHost = strings.TrimSpace(rawHost)
	if slash := strings.IndexByte(rawHost, '/'); slash >= 0 {
		rawHost = rawHost[:slash]
	}
	host, port, err := net.SplitHostPort(rawHost)
	if err != nil {
		host = strings.Trim(rawHost, "[]")
		port = "853"
	}
	addr := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: 4 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	defer tlsConn.Close()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(4 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = tlsConn.SetDeadline(deadline)

	var lenHdr [2]byte
	binary.BigEndian.PutUint16(lenHdr[:], uint16(len(wire)))
	if _, err := tlsConn.Write(append(lenHdr[:], wire...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(tlsConn, lenHdr[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenHdr[:]))
	if respLen < 12 || respLen > 16384 {
		return nil, errors.New("invalid DoT DNS response length")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(tlsConn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// encodeDNSQuery constructs an RFC 1035 standard recursive query packet.
func encodeDNSQuery(domain string, qtype uint16) ([]byte, uint16, error) {
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	txID := binary.BigEndian.Uint16(idBytes[:])
	if txID == 0 {
		txID = 1
	}

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

func decodeDNSAnswers(msg []byte, expectedID uint16, qtype uint16, allowZeroID bool) ([]netip.Addr, uint32, error) {
	return decodeDNSAnswersForDomain(msg, expectedID, "", qtype, allowZeroID)
}

func decodeDNSAnswersForDomain(msg []byte, expectedID uint16, expectedDomain string, qtype uint16, allowZeroID bool) ([]netip.Addr, uint32, error) {
	if len(msg) < 12 {
		return nil, 0, errors.New("short DNS packet")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	if id != expectedID && (!allowZeroID || id != 0) {
		return nil, 0, errors.New("DNS transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if (flags & 0x8000) == 0 {
		return nil, 0, errors.New("DNS QR bit not set (not a response)")
	}
	rcode := flags & 0x000F
	if rcode == 3 {
		return nil, 0, errDNSNXDomain
	}
	if rcode != 0 {
		return nil, 0, fmt.Errorf("DNS rcode=%d", rcode)
	}
	truncated := (flags & 0x0200) != 0
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	// Validate QDCOUNT == 1 to prevent cache poisoning via crafted multi-question responses
	if qdCount != 1 {
		return nil, 0, fmt.Errorf("DNS QDCOUNT=%d (expected 1)", qdCount)
	}

	pos := 12
	for i := 0; i < qdCount; i++ {
		qname, next, err := readDNSName(msg, pos)
		if err != nil || next+4 > len(msg) {
			return nil, 0, errors.New("malformed DNS question")
		}
		if expectedDomain != "" {
			want := strings.TrimSuffix(expectedDomain, ".")
			if !strings.EqualFold(qname, want) {
				return nil, 0, fmt.Errorf("DNS QNAME mismatch: got %q, want %q", qname, want)
			}
		}
		// Validate QTYPE matches the requested record type and QCLASS == IN (1)
		respQType := binary.BigEndian.Uint16(msg[next : next+2])
		if respQType != qtype {
			return nil, 0, fmt.Errorf("DNS QTYPE=%d (expected %d)", respQType, qtype)
		}
		qclass := binary.BigEndian.Uint16(msg[next+2 : next+4])
		if qclass != 1 {
			return nil, 0, fmt.Errorf("DNS QCLASS=%d (expected IN=1)", qclass)
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
		rrClass := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
		ttl := binary.BigEndian.Uint32(msg[pos+4 : pos+8])
		rdLen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdLen > len(msg) {
			break
		}
		rdata := msg[pos : pos+rdLen]
		pos += rdLen

		// Skip non-IN class RRs (prevents cache poisoning via injected CHAOS/etc class records)
		if rrClass != 1 {
			continue
		}

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
	if len(addrs) == 0 && truncated {
		return nil, 0, errDNSTruncated
	}
	return addrs, minTTL, nil
}

func readDNSName(msg []byte, pos int) (string, int, error) {
	var bld strings.Builder
	cur := pos
	nextPos := 0
	jumped := false
	ptrHops := 0
	labels := 0
	for cur < len(msg) {
		b := msg[cur]
		if b == 0 {
			if !jumped {
				nextPos = cur + 1
			}
			return bld.String(), nextPos, nil
		}
		if (b & 0xC0) == 0xC0 {
			if cur+1 >= len(msg) {
				return "", 0, errors.New("truncated pointer")
			}
			if !jumped {
				nextPos = cur + 2
				jumped = true
			}
			ptr := int(b&0x3F)<<8 | int(msg[cur+1])
			if ptr >= len(msg) {
				return "", 0, errors.New("pointer out of range")
			}
			cur = ptr
			ptrHops++
			if ptrHops > 16 {
				return "", 0, errors.New("compression pointer loop")
			}
			continue
		}
		if (b & 0xC0) != 0 {
			return "", 0, errors.New("invalid DNS label header")
		}
		l := int(b)
		if cur+1+l > len(msg) {
			return "", 0, errors.New("truncated DNS label")
		}
		if bld.Len() > 0 {
			bld.WriteByte('.')
		}
		if bld.Len()+l > 255 {
			return "", 0, errors.New("DNS name exceeds 255 bytes")
		}
		bld.Write(msg[cur+1 : cur+1+l])
		cur += 1 + l
		labels++
		if labels > 128 {
			return "", 0, errors.New("DNS name has too many labels")
		}
	}
	return "", 0, errors.New("unterminated DNS name")
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
		if (b & 0xC0) != 0 {
			return 0, errors.New("invalid DNS label header")
		}
		if pos+1+int(b) > len(msg) {
			return 0, errors.New("truncated DNS label")
		}
		pos += 1 + int(b)
		jumps++
		if jumps > 128 {
			return 0, errors.New("name too long")
		}
	}
	return 0, errors.New("unterminated DNS name")
}

func fallbackSystemResolveAll(ctx context.Context, host string, strat Strategy, filter bool) ([]netip.Addr, error) {
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
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	if filter && (strat == StrategyIPv4First || strat == StrategyIPv6First) {
		wantV4 := strat == StrategyIPv4First
		for _, ip := range ips {
			u := ip.Unmap()
			if u.Is4() == wantV4 {
				out = append(out, u)
			}
		}
		for _, ip := range ips {
			u := ip.Unmap()
			if u.Is4() != wantV4 {
				out = append(out, u)
			}
		}
		return out, nil
	}
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}

// maybeHotReload checks `/etc/xoga/dns.yml` mtime at most once every 5 seconds and hot-swaps rules!
func (r *Resolver) maybeHotReload() {
	// Skip hot-reload when driven by a remote dns_config_url or when no local dns.yml path exists;
	// otherwise reloadNow(false) would run with empty raw bytes and wipe rules + cache every 5s.
	if r.remoteURL != "" || r.configPath == "" {
		return
	}
	now := time.Now().Unix()
	prev := r.lastCheck.Load()
	if now-prev < 5 || !r.lastCheck.CompareAndSwap(prev, now) {
		return
	}
	r.reloadNow(false)
}

func (r *Resolver) reloadNow(initial bool) {
	if !initial && (r.remoteURL != "" || r.configPath == "") {
		return
	}
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	var raw []byte
	loaded := false
	if r.remoteURL != "" && initial {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.remoteURL, nil)
		if err == nil {
			if resp, derr := r.dohClient.Do(req); derr == nil {
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					if data, rerr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)); rerr == nil && len(data) > 0 {
						raw = data
						loaded = true
					}
				}
				_ = resp.Body.Close()
			}
		}
		cancel()
	}

	// When a remote URL is configured, skip local file hot-reload to prevent
	// overwriting remote config with stale local dns.yml on file mtime changes.
	if !loaded && r.configPath != "" && (r.remoteURL == "" || initial) {
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
		loaded = true
	}

	// Never overwrite the active snapshot or flush cache on a non-initial reload when nothing was loaded.
	if !initial && !loaded {
		return
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

func yamlIndent(line string) int {
	n := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ':
			n++
		case '\t':
			n += 2
		default:
			return n
		}
	}
	return n
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
	serverItemIndent := -1

	flush := func() {
		if cur != nil && cur.server != "" {
			hasPatterns := len(cur.exact) > 0 || len(cur.suffixMap) > 0 || len(cur.keywords) > 0 || len(cur.regexps) > 0
			if !hasPatterns && !cur.sawRulesKey {
				cur.isCatch = true
			}
			if hasPatterns || cur.isCatch {
				rules = append(rules, *cur)
			}
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

		indent := yamlIndent(line)

		// Top-level key (indent == 0)
		if indent == 0 && strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "-") {
			key := strings.TrimSpace(strings.TrimSuffix(trimmed, ":"))
			key = strings.Trim(key, "\"'")
			flush()
			inRulesList = false
			serverItemIndent = -1
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
			// Distinguish top-level `servers:` list items (at serverItemIndent) from nested
			// `domains:`/`rules:` patterns inside a structured server entry (deeper indent).
			isTopServerItem := serverItemIndent < 0 || indent <= serverItemIndent
			if isTopServerItem {
				serverItemIndent = indent
				item := strings.TrimSpace(trimmed[1:])
				lowerItem := strings.ToLower(item)
				// Support soga structured `servers:\n  - address: 1.1.1.1\n    domains: [...]` list items!
				if strings.HasPrefix(lowerItem, "address:") || strings.HasPrefix(lowerItem, "server:") {
					flush()
					inRulesList = false
					_, addrVal, _ := strings.Cut(item, ":")
					srv := strings.Trim(strings.TrimSpace(addrVal), "\"'")
					cur = &upstreamRule{
						server:   srv,
						strategy: defStrat,
						exact:    make(map[string]struct{}),
					}
					continue
				}
				if strings.HasPrefix(lowerItem, "strategy:") || strings.HasPrefix(lowerItem, "rules:") ||
					strings.HasPrefix(lowerItem, "domains:") || strings.HasPrefix(lowerItem, "match:") {
					flush()
					inRulesList = false
					cur = &upstreamRule{
						strategy: defStrat,
						exact:    make(map[string]struct{}),
					}
					trimmed = item
				} else {
					flush()
					inRulesList = false
					srv := strings.Trim(item, "\"'")
					if srv != "" && !strings.Contains(srv, ": ") {
						defaultServers = append(defaultServers, srv)
					}
					continue
				}
			}
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
		case "address", "server":
			if v != "" {
				cur.server = v
			}
			inRulesList = false
		case "strategy":
			cur.strategy = ParseStrategy(v)
			inRulesList = false
		case "rules", "domains", "match":
			cur.sawRulesKey = true
			if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
				inRulesList = false
				for _, item := range acl.SplitQuotedArrayItems(v[1 : len(v)-1]) {
					cur.addPattern(item)
				}
			} else {
				inRulesList = true
			}
		default:
			inRulesList = false
		}
	}
	flush()
	if len(defaultServers) == 0 {
		for _, r := range rules {
			if r.isCatch {
				defaultServers = append(defaultServers, r.server)
			}
		}
	}
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
	// Strip outer brackets from bare IPv6 addresses like "[::1]" before JoinHostPort
	addr = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
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
