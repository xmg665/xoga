package acl

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/logger"
)

var (
	zeroNetPrefix   = netip.MustParsePrefix("0.0.0.0/8")
	cgnatPrefix     = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkPrefix = netip.MustParsePrefix("198.18.0.0/15")
	reservedPrefix  = netip.MustParsePrefix("240.0.0.0/4")

	errRoutesEmpty = errors.New("empty routes.toml")
)

// IsReservedOrPrivateIP reports whether ip belongs to loopback, RFC1918 private, link-local,
// unspecified/this-network (`0.0.0.0/8`, `::`), multicast, RFC6598 CGNAT (`100.64.0.0/10`,
// cloud metadata `100.100.100.200`), RFC2544 benchmark/Fake-IP (`198.18.0.0/15`), or Class E
// reserved (`240.0.0.0/4`) space.
func IsReservedOrPrivateIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	if ip.Is4() {
		return zeroNetPrefix.Contains(ip) ||
			cgnatPrefix.Contains(ip) ||
			benchmarkPrefix.Contains(ip) ||
			reservedPrefix.Contains(ip)
	}
	return false
}

type Action uint8

const (
	ActionDirect Action = iota
	ActionBlock
	ActionProxy
)

// OutboundNode describes one concrete outbound endpoint (from `[[routes.outs]]`, `outbound = "..."`, or panel route).
type OutboundNode struct {
	Type           string // "direct", "block", "socks5", "http", "https", "ss", "shadowsocks", "trojan", "vless"
	Server         string
	Port           int
	Username       string
	Password       string
	UUID           string
	Cipher         string
	TLS            bool
	SNI            string
	SkipCertVerify bool
	Network        string // "tcp", "ws"
	WSPath         string
	ListenIPv4     string
	ListenIPv6     string
	ListenStrategy string // "ipv4_first", "ipv6_first", "ipv4_only", "ipv6_only"
}

// OutboundTarget represents the resolved routing decision for a connection, including
// ordered candidate outbounds for load-balancing and automatic failover.
type OutboundTarget struct {
	Action        Action
	RuleName      string
	MatchedRule   bool
	IsRemoteProxy bool
	ForbidPrivate bool
	Outbounds     []OutboundNode
	eng           *Engine
}

// AllowResolvedIP validates post-DNS resolved target IPs against both `blockList` CIDRs and
// `ban_private_ip=true` (preventing DNS rebinding / `127.0.0.1.nip.io` SSRF bypasses).
func (o OutboundTarget) AllowResolvedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if o.eng != nil {
		if sn := o.eng.snap.Load(); sn != nil {
			if sn.whitelist.matchesIP(ip) {
				return true
			}
			if sn.blocklist.matchesIP(ip) {
				return false
			}
		}
	}
	if o.ForbidPrivate && IsReservedOrPrivateIP(ip) {
		return false
	}
	return true
}

type compiledRule struct {
	name              string
	balance           string // "round_robin", "random", "first"
	rrCounter         *atomic.Uint64
	nodeIDs           map[int]struct{}
	hasTargetCriteria bool
	exactDomains      map[string]struct{}
	suffixMap         map[string]struct{}
	keywords          []string
	regexps           []*regexp.Regexp
	prefixes          []netip.Prefix
	protocols         map[string]struct{}
	action            Action
	outs              []OutboundNode
}

func (r *compiledRule) selectOutbounds() OutboundTarget {
	isRemote := r.action == ActionProxy && len(r.outs) > 0 && r.outs[0].Type != "direct" && r.outs[0].Type != ""
	if r.action != ActionProxy || len(r.outs) <= 1 {
		return OutboundTarget{
			Action:        r.action,
			RuleName:      r.name,
			MatchedRule:   true,
			IsRemoteProxy: isRemote,
			Outbounds:     r.outs,
		}
	}
	n := len(r.outs)
	start := 0
	switch r.balance {
	case "random":
		start = rand.IntN(n)
	case "first", "":
		start = 0
	default: // round_robin
		start = int(r.rrCounter.Add(1)-1) % n
	}
	ordered := make([]OutboundNode, n)
	for i := 0; i < n; i++ {
		ordered[i] = r.outs[(start+i)%n]
	}
	return OutboundTarget{
		Action:        r.action,
		RuleName:      r.name,
		MatchedRule:   true,
		IsRemoteProxy: ordered[0].Type != "direct" && ordered[0].Type != "",
		Outbounds:     ordered,
	}
}

type DynamicRoute struct {
	Matches     []string
	Action      string // "block", "dns", "direct", "proxy", "default_out"
	ActionValue string
}

type aclSnapshot struct {
	whitelist  compiledRule
	blocklist  compiledRule
	fileRoutes []compiledRule
	routes     []compiledRule
}

type fileStat struct {
	modTime time.Time
	size    int64
	exists  bool
}

// Engine evaluates whitelist, blocklist, BitTorrent policy, and panel/local route rules
// with automatic 5-second mtime hot-reloading of `blockList`, `whiteList`, and `routes.toml`.
type Engine struct {
	forbidBT       bool
	banPrivateIP   bool
	forbiddenPorts [1024]uint64 // 65,536-bit O(1) port block bitmap (8 KiB)
	hasPortRules   bool
	whitePath      string
	blockPath      string
	routesPath     string
	panelRoutes    []DynamicRoute

	snap atomic.Pointer[aclSnapshot]

	reloadMu  sync.Mutex
	whiteStat fileStat
	blockStat fileStat
	routeStat fileStat
	lastCheck atomic.Int64
}

func NewEngine(forbidBT bool, whitePath, blockPath, routesPath string, panelRoutes []DynamicRoute) *Engine {
	e := &Engine{
		forbidBT:    forbidBT,
		whitePath:   whitePath,
		blockPath:   blockPath,
		routesPath:  routesPath,
		panelRoutes: panelRoutes,
	}
	e.reloadNow(true)
	return e
}

func (e *Engine) maybeHotReload() {
	now := time.Now().Unix()
	prev := e.lastCheck.Load()
	if now-prev < 5 || !e.lastCheck.CompareAndSwap(prev, now) {
		return
	}
	e.reloadNow(false)
}

func (e *Engine) reloadNow(initial bool) {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	wStat := statFile(e.whitePath)
	bStat := statFile(e.blockPath)
	rStat := statFile(e.routesPath)

	wChanged := initial || wStat != e.whiteStat
	bChanged := initial || bStat != e.blockStat
	rChanged := initial || rStat != e.routeStat
	if !wChanged && !bChanged && !rChanged {
		return
	}

	prevSnap := e.snap.Load()
	sn := &aclSnapshot{
		whitelist: newCompiledRule("whitelist", ActionDirect),
		blocklist: newCompiledRule("blocklist", ActionBlock),
	}

	var appliedAny bool

	// 1. whiteList: read and parse BEFORE updating whiteStat
	if wChanged {
		if e.whitePath == "" || !wStat.exists {
			e.whiteStat = wStat
			appliedAny = true
		} else if lines, err := readRuleLines(e.whitePath); err == nil {
			for _, l := range lines {
				sn.whitelist.addPattern(l)
			}
			e.whiteStat = wStat
			appliedAny = true
		} else if errors.Is(err, os.ErrNotExist) {
			e.whiteStat = fileStat{}
			appliedAny = true
		} else {
			logger.Warnf("whiteList reload failed (%v); retaining previous rules", err)
			if prevSnap != nil {
				sn.whitelist = prevSnap.whitelist
			}
		}
	} else if prevSnap != nil {
		sn.whitelist = prevSnap.whitelist
	}

	// 2. blockList: read and parse BEFORE updating blockStat
	if bChanged {
		if e.blockPath == "" || !bStat.exists {
			e.blockStat = bStat
			appliedAny = true
		} else if lines, err := readRuleLines(e.blockPath); err == nil {
			for _, l := range lines {
				sn.blocklist.addPattern(l)
			}
			e.blockStat = bStat
			appliedAny = true
		} else if errors.Is(err, os.ErrNotExist) {
			e.blockStat = fileStat{}
			appliedAny = true
		} else {
			logger.Warnf("blockList reload failed (%v); retaining previous rules", err)
			if prevSnap != nil {
				sn.blocklist = prevSnap.blocklist
			}
		}
	} else if prevSnap != nil {
		sn.blocklist = prevSnap.blocklist
	}

	// 3. routes.toml: read and validate BEFORE updating routeStat so transient truncation /
	// partial writes never wipe active routes or latch a broken mtime.
	var prevFileRoutes []compiledRule
	if prevSnap != nil {
		prevFileRoutes = prevSnap.fileRoutes
	}
	if rChanged {
		if e.routesPath == "" || !rStat.exists {
			e.routeStat = rStat
			appliedAny = true
		} else {
			parsed, explicitlyDisabled, rerr := parseRoutesTOMLFile(e.routesPath)
			switch {
			case rerr != nil && errors.Is(rerr, os.ErrNotExist):
				e.routeStat = fileStat{}
				appliedAny = true
			case !initial && len(prevFileRoutes) > 0 && (rerr != nil || (!explicitlyDisabled && len(parsed) == 0)):
				reason := "produced 0 routes"
				if rerr != nil {
					reason = rerr.Error()
				}
				logger.Warnf("routes.toml reload skipped (%s); retaining %d previous route rules", reason, len(prevFileRoutes))
				sn.fileRoutes = prevFileRoutes
			case rerr != nil && !errors.Is(rerr, errRoutesEmpty):
				logger.Warnf("routes.toml parse failed (%v); retaining previous route rules", rerr)
				sn.fileRoutes = prevFileRoutes
			default:
				sn.fileRoutes = parsed
				e.routeStat = rStat
				appliedAny = true
			}
		}
	} else {
		sn.fileRoutes = prevFileRoutes
	}

	if !initial && !appliedAny {
		return
	}

	if len(sn.fileRoutes) > 0 {
		sn.routes = append(sn.routes, sn.fileRoutes...)
	}
	for _, pr := range e.panelRoutes {
		act := strings.ToLower(strings.TrimSpace(pr.Action))
		var cr compiledRule
		switch act {
		case "block":
			cr = newCompiledRule("panel-block", ActionBlock)
		case "direct", "default_out":
			val := strings.TrimSpace(pr.ActionValue)
			if val == "" {
				cr = newCompiledRule("panel-direct", ActionDirect)
			} else if node, ok := ParseOutboundURL(val); ok {
				a := ActionProxy
				if node.Type == "direct" && node.ListenIPv4 == "" && node.ListenIPv6 == "" && node.ListenStrategy == "" {
					a = ActionDirect
				}
				cr = newCompiledRule("panel-route", a)
				cr.outs = []OutboundNode{node}
			} else {
				cr = newCompiledRule("panel-direct", ActionDirect)
			}
		case "proxy", "socks5", "http", "ss", "trojan", "vless":
			node, ok := ParseOutboundURL(strings.TrimSpace(pr.ActionValue))
			if !ok {
				continue
			}
			a := ActionProxy
			if node.Type == "direct" {
				a = ActionDirect
			}
			cr = newCompiledRule("panel-route", a)
			cr.outs = []OutboundNode{node}
		default:
			continue
		}
		for _, m := range pr.Matches {
			cr.addPattern(m)
		}
		sn.routes = append(sn.routes, cr)
	}

	e.snap.Store(sn)
	if !initial && appliedAny {
		logger.Infof("Hot-reloaded ACL & routes.toml (%d custom route rules)", len(sn.routes))
	}
}

// SetPortAndPrivatePolicy configures soga-compatible `forbidden_ports=25,26,6881-6999` and `ban_private_ip`.
func (e *Engine) SetPortAndPrivatePolicy(forbiddenPorts string, banPrivate bool) {
	if e == nil {
		return
	}
	e.banPrivateIP = banPrivate
	e.forbiddenPorts = [1024]uint64{}
	e.hasPortRules = false
	for _, part := range strings.Split(forbiddenPorts, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, ok := strings.Cut(part, "-"); ok {
			lo, err1 := strconv.Atoi(strings.TrimSpace(loStr))
			hi, err2 := strconv.Atoi(strings.TrimSpace(hiStr))
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo && hi <= 65535 {
				for p := lo; p <= hi; p++ {
					e.forbiddenPorts[p>>6] |= 1 << uint(p&63)
				}
				e.hasPortRules = true
			}
		} else if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
			e.forbiddenPorts[p>>6] |= 1 << uint(p&63)
			e.hasPortRules = true
		}
	}
}

func (e *Engine) IsPortForbidden(port uint16) bool {
	if e == nil || !e.hasPortRules || port == 0 {
		return false
	}
	return (e.forbiddenPorts[port>>6] & (1 << uint(port&63))) != 0
}

// IsIPWhitelisted reports whether ip explicitly matches `/etc/xoga/whiteList` IP/CIDR rules.
func (e *Engine) IsIPWhitelisted(ip netip.Addr) bool {
	if e == nil || !ip.IsValid() {
		return false
	}
	e.maybeHotReload()
	sn := e.snap.Load()
	if sn == nil {
		return false
	}
	return sn.whitelist.matchesIP(ip.Unmap())
}

// HasRouteForDomain reports whether any non-direct proxy route in `routes.toml` or panel routes matches domain.
func (e *Engine) HasRouteForDomain(domain string) bool {
	if e == nil || domain == "" {
		return false
	}
	e.maybeHotReload()
	sn := e.snap.Load()
	if sn == nil {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for i := range sn.routes {
		if sn.routes[i].matchDomain(d) {
			return sn.routes[i].action == ActionProxy
		}
	}
	return false
}

// DecideWithPort checks port bans (`forbidden_ports`), private IP policy, and domain/IP routing rules.
func (e *Engine) DecideWithPort(destHost string, destPort uint16, sniffDomain string, sniffProto string) OutboundTarget {
	return e.DecideForNode(0, destHost, destPort, sniffDomain, sniffProto)
}

// DecideForNode evaluates port bans, private IP policy, and node_id/domain/IP routing rules
// (supporting multi-node soga `rules=["node_id:781"]` + `listen="10.163.0.100"` exit binding).
func (e *Engine) DecideForNode(nodeID int, destHost string, destPort uint16, sniffDomain string, sniffProto string) OutboundTarget {
	if e != nil && e.IsPortForbidden(destPort) {
		return OutboundTarget{Action: ActionBlock, RuleName: "forbidden-port", MatchedRule: true}
	}
	res := e.decideInternal(nodeID, destHost, sniffDomain, sniffProto)
	if e != nil {
		if e.banPrivateIP && res.RuleName != "whitelist" && res.Action != ActionBlock {
			if ip, err := netip.ParseAddr(destHost); err == nil && IsReservedOrPrivateIP(ip) {
				return OutboundTarget{Action: ActionBlock, RuleName: "ban-private-ip", MatchedRule: true, eng: e, ForbidPrivate: true}
			}
		}
		res.eng = e
		res.ForbidPrivate = e.banPrivateIP && res.RuleName != "whitelist"
	}
	return res
}

// Decide evaluates target host/IP and sniffed protocol/domain, returning the outbound action.
func (e *Engine) Decide(destHost string, sniffDomain string, sniffProto string) OutboundTarget {
	res := e.decideInternal(0, destHost, sniffDomain, sniffProto)
	if e != nil {
		res.eng = e
		res.ForbidPrivate = e.banPrivateIP && res.RuleName != "whitelist"
	}
	return res
}

func (e *Engine) decideInternal(nodeID int, destHost string, sniffDomain string, sniffProto string) OutboundTarget {
	if e == nil {
		return OutboundTarget{Action: ActionDirect}
	}
	if e.forbidBT && sniffProto == "bittorrent" {
		return OutboundTarget{Action: ActionBlock, RuleName: "forbid-bt", MatchedRule: true}
	}

	e.maybeHotReload()
	sn := e.snap.Load()
	if sn == nil {
		return OutboundTarget{Action: ActionDirect}
	}

	var ip netip.Addr
	if parsed, err := netip.ParseAddr(destHost); err == nil {
		ip = parsed.Unmap()
	}

	host := strings.ToLower(strings.TrimSuffix(destHost, "."))
	sdom := strings.ToLower(strings.TrimSuffix(sniffDomain, "."))

	if sn.whitelist.matches(nodeID, host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionDirect, RuleName: "whitelist", MatchedRule: true}
	}
	if sn.blocklist.matches(nodeID, host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionBlock, RuleName: "blocklist", MatchedRule: true}
	}
	for i := range sn.routes {
		if sn.routes[i].matches(nodeID, host, sdom, ip, sniffProto) {
			return sn.routes[i].selectOutbounds()
		}
	}
	return OutboundTarget{Action: ActionDirect}
}

func newCompiledRule(name string, act Action) compiledRule {
	return compiledRule{
		name:         name,
		balance:      "round_robin",
		rrCounter:    new(atomic.Uint64),
		exactDomains: make(map[string]struct{}),
		suffixMap:    make(map[string]struct{}),
		protocols:    make(map[string]struct{}),
		action:       act,
	}
}

func (r *compiledRule) addNodeIDSpec(spec string) {
	if r.nodeIDs == nil {
		r.nodeIDs = make(map[int]struct{})
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, ok := strings.Cut(part, "-"); ok {
			lo, err1 := strconv.Atoi(strings.TrimSpace(loStr))
			hi, err2 := strconv.Atoi(strings.TrimSpace(hiStr))
			if err1 == nil && err2 == nil && lo > 0 && hi >= lo && hi-lo <= 1000 {
				for id := lo; id <= hi; id++ {
					r.nodeIDs[id] = struct{}{}
				}
			}
		} else if id, err := strconv.Atoi(part); err == nil && id > 0 {
			r.nodeIDs[id] = struct{}{}
		}
	}
}

func (r *compiledRule) addPattern(raw string) {
	p := strings.TrimSpace(raw)
	if p == "" || strings.HasPrefix(p, "#") {
		return
	}
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "node_id:") || strings.HasPrefix(lower, "node:") {
		_, val, _ := strings.Cut(p, ":")
		r.addNodeIDSpec(val)
		return
	}
	if p == "*" || strings.EqualFold(p, "all") || strings.EqualFold(p, "any") {
		r.hasTargetCriteria = true
		r.prefixes = append(r.prefixes,
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		)
		r.regexps = append(r.regexps, regexp.MustCompile(`.`))
		return
	}
	if expanded, ok := ExpandGeosite(p); ok {
		for _, sub := range expanded {
			r.addPattern(sub)
		}
		return
	}
	if strings.HasPrefix(lower, "geosite:") {
		return
	}
	if strings.HasPrefix(lower, "protocol:") {
		r.hasTargetCriteria = true
		r.protocols[strings.TrimSpace(lower[9:])] = struct{}{}
		return
	}
	if lower == "bittorrent" {
		r.hasTargetCriteria = true
		r.protocols["bittorrent"] = struct{}{}
		return
	}
	if strings.HasPrefix(lower, "full:") {
		d := strings.TrimSuffix(strings.TrimSpace(lower[5:]), ".")
		if d != "" {
			r.hasTargetCriteria = true
			r.exactDomains[d] = struct{}{}
		}
		return
	}
	if strings.HasPrefix(lower, "domain:") {
		s := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(lower[7:]), "."), ".")
		if s != "" {
			r.hasTargetCriteria = true
			r.suffixMap[s] = struct{}{}
		}
		return
	}
	if strings.HasPrefix(lower, "keyword:") {
		k := strings.TrimSpace(lower[8:])
		if k != "" {
			r.hasTargetCriteria = true
			r.keywords = append(r.keywords, k)
		}
		return
	}
	if strings.HasPrefix(lower, "regexp:") {
		expr := strings.TrimSpace(p[7:])
		if expr != "" && !strings.HasPrefix(expr, "(?i)") {
			expr = "(?i)" + expr
		}
		if re, err := regexp.Compile(expr); err == nil {
			r.hasTargetCriteria = true
			r.regexps = append(r.regexps, re)
		}
		return
	}
	if pfx, err := netip.ParsePrefix(p); err == nil {
		r.hasTargetCriteria = true
		r.prefixes = append(r.prefixes, pfx.Masked())
		return
	}
	if addr, err := netip.ParseAddr(p); err == nil {
		r.hasTargetCriteria = true
		addr = addr.Unmap()
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		r.prefixes = append(r.prefixes, netip.PrefixFrom(addr, bits))
		return
	}
	s := strings.TrimPrefix(lower, "*.")
	s = strings.TrimPrefix(s, ".")
	if s != "" {
		r.hasTargetCriteria = true
		r.suffixMap[s] = struct{}{}
	}
}

func (r *compiledRule) matches(nodeID int, host, sdom string, ip netip.Addr, proto string) bool {
	if len(r.nodeIDs) > 0 {
		if nodeID <= 0 {
			return false
		}
		if _, ok := r.nodeIDs[nodeID]; !ok {
			return false
		}
		if !r.hasTargetCriteria {
			return true
		}
	} else if !r.hasTargetCriteria {
		return false
	}
	if proto != "" {
		if _, ok := r.protocols[proto]; ok {
			return true
		}
	}
	if ip.IsValid() {
		for _, pfx := range r.prefixes {
			if pfx.Contains(ip) {
				return true
			}
		}
	}
	if host != "" && !ip.IsValid() && r.matchDomain(host) {
		return true
	}
	if sdom != "" && sdom != host && r.matchDomain(sdom) {
		return true
	}
	return false
}

func (r *compiledRule) matchesIP(ip netip.Addr) bool {
	if !ip.IsValid() || len(r.nodeIDs) > 0 {
		return false
	}
	for _, pfx := range r.prefixes {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// matchDomain performs O(labels) zero-allocation label-boundary map lookup (xray-core / mihomo style)
// instead of O(N) suffix scanning, scaling cleanly to tens of thousands of domains.
func (r *compiledRule) matchDomain(d string) bool {
	if _, ok := r.exactDomains[d]; ok {
		return true
	}
	if len(r.suffixMap) > 0 {
		for cur := d; ; {
			if _, ok := r.suffixMap[cur]; ok {
				return true
			}
			dot := strings.IndexByte(cur, '.')
			if dot < 0 {
				break
			}
			cur = cur[dot+1:]
		}
	}
	for _, kw := range r.keywords {
		if strings.Contains(d, kw) {
			return true
		}
	}
	for _, re := range r.regexps {
		if re.MatchString(d) {
			return true
		}
	}
	return false
}

func statFile(path string) fileStat {
	if path == "" {
		return fileStat{}
	}
	if st, err := os.Stat(path); err == nil {
		return fileStat{modTime: st.ModTime(), size: st.Size(), exists: true}
	}
	return fileStat{}
}

func readRuleLines(path string) ([]string, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// ParseOutboundURL parses concise URL outbounds such as:
// - `socks5://user:pass@127.0.0.1:40000`
// - `http://user:pass@1.2.3.4:8080`
// - `ss://aes-256-gcm:password@1.2.3.4:8388`
// - `trojan://password@unlock.example.com:443?sni=unlock.example.com&allowInsecure=1`
// - `vless://uuid@unlock.example.com:443?security=tls&type=ws&path=/ws&sni=unlock.example.com`
// - `direct://?strategy=ipv6_only&v6=2001:db8::1`
func ParseOutboundURL(raw string) (OutboundNode, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return OutboundNode{}, false
	}
	if strings.EqualFold(raw, "block") {
		return OutboundNode{Type: "block"}, true
	}
	if strings.EqualFold(raw, "direct") {
		return OutboundNode{Type: "direct"}, true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return OutboundNode{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "socks5h" {
		scheme = "socks5"
	}
	host, portStr, herr := net.SplitHostPort(u.Host)
	if herr != nil {
		host = u.Host
	}
	port, _ := strconv.Atoi(portStr)
	q := u.Query()

	node := OutboundNode{
		Type:           scheme,
		Server:         strings.Trim(host, "[]"),
		Port:           port,
		SNI:            firstNonEmpty(q.Get("sni"), q.Get("peer")),
		SkipCertVerify: q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" || q.Get("skip_cert_verify") == "true",
		Network:        strings.ToLower(firstNonEmpty(q.Get("type"), q.Get("network"), "tcp")),
		WSPath:         q.Get("path"),
		ListenIPv4:     q.Get("v4"),
		ListenIPv6:     q.Get("v6"),
		ListenStrategy: q.Get("strategy"),
	}
	if q.Get("security") == "tls" || q.Get("tls") == "1" || q.Get("tls") == "true" || scheme == "trojan" || scheme == "https" {
		node.TLS = true
	}
	if u.User != nil {
		usr := u.User.Username()
		pw, hasPw := u.User.Password()
		switch scheme {
		case "ss", "shadowsocks":
			node.Type = "ss"
			if hasPw {
				node.Cipher = strings.ToLower(usr)
				node.Password = pw
			} else if decoded, ok := decodeSIP002Userinfo(usr); ok {
				m, p, _ := strings.Cut(decoded, ":")
				node.Cipher = strings.ToLower(m)
				node.Password = p
			} else {
				node.Cipher = strings.ToLower(firstNonEmpty(q.Get("method"), "aes-256-gcm"))
				node.Password = usr
			}
		case "trojan":
			node.Password = usr
		case "vless":
			node.UUID = usr
		default:
			node.Username = usr
			node.Password = pw
		}
	}
	return node, true
}

// ParseRoutesTOML parses soga-compatible `routes.toml` supporting:
// 1. `[[routes]]` with nested `[[routes.outs]]` (`type = "socks5"|"http"|"ss"|"trojan"|"vless"|"direct"|"block"`, `balance`, `listen_ipv4`/`ipv6`, `listen_strategy`)
// 2. Concise `[[routes]]` with `outbound = "socks5://..."`
// 3. Xray-style `[[outbound]]` (`tag = "..."`) + `[[rule]]` (`domain = [...]`, `outboundTag = "..."`)
func ParseRoutesTOML(path string) []compiledRule {
	routes, _, err := parseRoutesTOMLFile(path)
	if err != nil {
		return nil
	}
	return routes
}

func parseRoutesTOMLFile(path string) ([]compiledRule, bool, error) {
	if path == "" {
		return nil, false, os.ErrNotExist
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if len(bytes.TrimSpace(rawBytes)) == 0 {
		return nil, false, errRoutesEmpty
	}

	// Coalesce multi-line `[ ... ]` arrays into single lines for clean zero-dependency TOML parsing
	lines, unclosed := coalesceMultilineArraysChecked(string(rawBytes))
	if unclosed {
		return nil, false, errors.New("truncated or unclosed TOML array/section")
	}
	if len(lines) == 0 {
		return nil, false, errRoutesEmpty
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "[") && (!strings.HasSuffix(l, "]") || countBrackets(l) != 0) {
			return nil, false, errors.New("malformed TOML section header")
		}
	}

	type routeDraft struct {
		enable   bool
		name     string
		balance  string
		action   string
		outbound string
		outTag   string
		matches  []string
		outs     []OutboundNode
	}

	var drafts []routeDraft
	namedOutbounds := make(map[string]OutboundNode)
	fileEnabled := true

	mode := "" // "route", "route_out", "named_out"
	var curNamedTag string
	var curNamedNode OutboundNode

	flushNamed := func() {
		if curNamedTag != "" && curNamedNode.Type != "" {
			namedOutbounds[curNamedTag] = curNamedNode
		}
		curNamedTag = ""
		curNamedNode = OutboundNode{}
	}

	for _, l := range lines {
		switch strings.ToLower(l) {
		case "[[routes]]", "[[route]]", "[[rule]]":
			flushNamed()
			drafts = append(drafts, routeDraft{enable: true, balance: "round_robin"})
			mode = "route"
			continue
		case "[[routes.outs]]", "[[route.outs]]", "[[outs]]":
			flushNamed()
			if len(drafts) == 0 {
				drafts = append(drafts, routeDraft{enable: true, balance: "round_robin"})
			}
			drafts[len(drafts)-1].outs = append(drafts[len(drafts)-1].outs, OutboundNode{Network: "tcp"})
			mode = "route_out"
			continue
		case "[[outbound]]", "[[outbounds]]":
			flushNamed()
			curNamedNode = OutboundNode{Network: "tcp"}
			mode = "named_out"
			continue
		}
		if strings.HasPrefix(l, "[") {
			flushNamed()
			mode = ""
			continue
		}

		eq := strings.IndexByte(l, '=')
		if eq <= 0 {
			return nil, false, errors.New("malformed or truncated TOML key-value line")
		}
		k := strings.TrimSpace(l[:eq])
		v := stripTOMLComment(strings.TrimSpace(l[eq+1:]))
		unquoted := strings.Trim(v, "\"'")

		if mode == "" {
			if strings.EqualFold(k, "enable") || strings.EqualFold(k, "enabled") {
				fileEnabled = !strings.EqualFold(unquoted, "false")
			}
			continue
		}

		switch mode {
		case "route":
			d := &drafts[len(drafts)-1]
			switch strings.ToLower(k) {
			case "enable", "enabled":
				d.enable = !strings.EqualFold(unquoted, "false")
			case "name", "tag":
				d.name = unquoted
			case "balance":
				d.balance = strings.ToLower(unquoted)
			case "action", "type":
				if unquoted != "field" {
					d.action = strings.ToLower(unquoted)
				}
			case "outbound", "address", "proxy", "url":
				d.outbound = unquoted
			case "outboundtag", "outbound_tag":
				d.outTag = unquoted
			case "node_id", "node_ids":
				for _, item := range parseTOMLStringArray(v) {
					d.matches = append(d.matches, "node_id:"+item)
				}
			case "rules", "match", "domain", "domains", "ip":
				d.matches = append(d.matches, parseTOMLStringArray(v)...)
			}
		case "route_out":
			d := &drafts[len(drafts)-1]
			out := &d.outs[len(d.outs)-1]
			applyOutboundKV(out, k, unquoted)
		case "named_out":
			if strings.EqualFold(k, "tag") || strings.EqualFold(k, "name") {
				curNamedTag = unquoted
			} else {
				applyOutboundKV(&curNamedNode, k, unquoted)
			}
		}
	}
	flushNamed()
	if !fileEnabled {
		return nil, true, nil
	}

	var compiled []compiledRule
	hasEnabledDraft := false
	for i, d := range drafts {
		if !d.enable {
			continue
		}
		hasEnabledDraft = true
		if len(d.matches) == 0 {
			continue
		}
		name := d.name
		if name == "" {
			name = "route-" + strconv.Itoa(i+1)
		}
		if d.outTag != "" {
			if named, ok := namedOutbounds[d.outTag]; ok {
				d.outs = append(d.outs, named)
			} else if strings.EqualFold(d.outTag, "block") {
				d.action = "block"
			} else if strings.EqualFold(d.outTag, "direct") {
				d.action = "direct"
			}
		}
		if d.outbound != "" {
			if parsed, ok := ParseOutboundURL(d.outbound); ok {
				d.outs = append(d.outs, parsed)
			} else if named, ok := namedOutbounds[d.outbound]; ok {
				d.outs = append(d.outs, named)
			}
		}

		act := ActionProxy
		if d.action == "block" || (len(d.outs) == 1 && d.outs[0].Type == "block") {
			act = ActionBlock
		} else if len(d.outs) == 0 && d.action == "direct" {
			act = ActionDirect
		} else if len(d.outs) == 1 && d.outs[0].Type == "direct" && d.outs[0].ListenIPv4 == "" && d.outs[0].ListenIPv6 == "" && d.outs[0].ListenStrategy == "" {
			act = ActionDirect
		} else if len(d.outs) == 0 {
			logger.Warnf("routes.toml: skipping route %q with unresolved outbound (tag=%q outbound=%q)", name, d.outTag, d.outbound)
			continue
		}

		cr := newCompiledRule(name, act)
		cr.balance = d.balance
		cr.outs = d.outs
		for _, m := range d.matches {
			cr.addPattern(m)
		}
		compiled = append(compiled, cr)
	}
	if len(drafts) > 0 && !hasEnabledDraft {
		return nil, true, nil
	}
	return compiled, false, nil
}

func applyOutboundKV(out *OutboundNode, k, v string) {
	switch strings.ToLower(k) {
	case "type", "protocol":
		t := strings.ToLower(v)
		switch t {
		case "shadowsocks":
			t = "ss"
		case "socks", "socks5h":
			t = "socks5"
		case "freedom":
			t = "direct"
		case "blackhole":
			t = "block"
		}
		out.Type = t
	case "server", "address", "host":
		out.Server = v
	case "port":
		out.Port, _ = strconv.Atoi(v)
	case "username", "user":
		out.Username = v
	case "password", "passwd":
		out.Password = v
	case "uuid", "id":
		out.UUID = v
	case "cipher", "method":
		out.Cipher = strings.ToLower(v)
	case "tls":
		out.TLS = strings.EqualFold(v, "true") || v == "1"
	case "sni", "server_name":
		out.SNI = v
	case "skip_cert_verify", "allow_insecure":
		out.SkipCertVerify = strings.EqualFold(v, "true") || v == "1"
	case "network", "net":
		out.Network = strings.ToLower(v)
	case "ws_path", "path":
		out.WSPath = v
	case "listen", "out_ip", "send_through", "sendthrough", "local_addr":
		if ip, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
			ip = ip.Unmap()
			if ip.Is4() {
				out.ListenIPv4 = ip.String()
			} else {
				out.ListenIPv6 = ip.String()
			}
		}
	case "listen_ipv4":
		out.ListenIPv4 = v
	case "listen_ipv6":
		out.ListenIPv6 = v
	case "listen_strategy", "strategy":
		out.ListenStrategy = strings.ToLower(v)
	case "url":
		if parsed, ok := ParseOutboundURL(v); ok {
			*out = parsed
		}
	}
}

func coalesceMultilineArrays(raw string) []string {
	out, _ := coalesceMultilineArraysChecked(raw)
	return out
}

func coalesceMultilineArraysChecked(raw string) ([]string, bool) {
	var out []string
	var buf strings.Builder
	bracketDepth := 0

	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(stripTOMLComment(sc.Text()))
		if line == "" {
			continue
		}
		if hasUnclosedQuote(line) {
			return nil, true
		}
		if bracketDepth > 0 {
			buf.WriteByte(' ')
			buf.WriteString(line)
			bracketDepth += countBrackets(line)
			if bracketDepth <= 0 {
				if bracketDepth < 0 {
					return nil, true
				}
				bracketDepth = 0
				out = append(out, buf.String())
				buf.Reset()
			}
			continue
		}
		delta := countBrackets(line)
		// Note: `[[routes]]` has 2 `[` and 2 `]`, so delta == 0!
		if delta > 0 && !strings.HasPrefix(line, "[") {
			bracketDepth = delta
			buf.WriteString(line)
			continue
		}
		if delta < 0 {
			return nil, true
		}
		out = append(out, line)
	}
	if sc.Err() != nil || bracketDepth != 0 || buf.Len() > 0 {
		return nil, true
	}
	return out, false
}

func hasUnclosedQuote(s string) bool {
	inQ := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			if escaped {
				escaped = false
				continue
			}
			if inQ == '"' && c == '\\' {
				escaped = true
				continue
			}
			if c == inQ {
				inQ = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQ = c
		}
	}
	return inQ != 0
}

func countBrackets(s string) int {
	inQ := byte(0)
	escaped := false
	d := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			if escaped {
				escaped = false
				continue
			}
			if inQ == '"' && c == '\\' {
				escaped = true
				continue
			}
			if c == inQ {
				inQ = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQ = c
		case '[':
			d++
		case ']':
			d--
		}
	}
	return d
}

func stripTOMLComment(s string) string {
	inQ := byte(0)
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			if escaped {
				escaped = false
				continue
			}
			if inQ == '"' && c == '\\' {
				escaped = true
				continue
			}
			if c == inQ {
				inQ = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQ = c
		} else if c == '#' {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func decodeSIP002Userinfo(s string) (string, bool) {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.StdEncoding} {
		in := trimmed
		if enc == base64.URLEncoding || enc == base64.StdEncoding {
			in = s
		}
		if b, err := enc.DecodeString(in); err == nil && strings.Contains(string(b), ":") {
			return string(b), true
		}
	}
	return "", false
}

// SplitQuotedArrayItems splits a comma-separated array body while respecting `"..."` and `'...'`
// quotes so patterns like `"node_id:781,782"` or `"regexp:^a{1,3}\\.com$"` are never split mid-string!
func SplitQuotedArrayItems(v string) []string {
	var out []string
	var cur strings.Builder
	inQ := byte(0)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if inQ != 0 {
			if c == '\\' && i+1 < len(v) {
				i++
				cur.WriteByte(v[i])
				continue
			}
			if c == inQ {
				inQ = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '"', '\'':
			inQ = c
		case ',':
			item := strings.TrimSpace(cur.String())
			if item != "" {
				out = append(out, item)
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if last := strings.TrimSpace(cur.String()); last != "" {
		out = append(out, last)
	}
	return out
}

func parseTOMLStringArray(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	return SplitQuotedArrayItems(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
