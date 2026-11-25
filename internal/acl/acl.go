package acl

import (
	"bufio"
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
	Action    Action
	RuleName  string
	MatchedRule bool
	Outbounds []OutboundNode
}

type compiledRule struct {
	name         string
	balance      string // "round_robin", "random", "first"
	rrCounter    *atomic.Uint64
	exactDomains map[string]struct{}
	suffixes     []string
	keywords     []string
	regexps      []*regexp.Regexp
	prefixes     []netip.Prefix
	protocols    map[string]struct{}
	action       Action
	outs         []OutboundNode
}

func (r *compiledRule) selectOutbounds() OutboundTarget {
	if r.action != ActionProxy || len(r.outs) <= 1 {
		return OutboundTarget{
			Action:      r.action,
			RuleName:    r.name,
			MatchedRule: true,
			Outbounds:   r.outs,
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
		Action:      r.action,
		RuleName:    r.name,
		MatchedRule: true,
		Outbounds:   ordered,
	}
}

type DynamicRoute struct {
	Matches     []string
	Action      string // "block", "dns", "direct", "proxy", "default_out"
	ActionValue string
}

type aclSnapshot struct {
	whitelist compiledRule
	blocklist compiledRule
	routes    []compiledRule
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

	reloadMu   sync.Mutex
	whiteMtime time.Time
	blockMtime time.Time
	routeMtime time.Time
	lastCheck  atomic.Int64
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

	wMod := statMtime(e.whitePath)
	bMod := statMtime(e.blockPath)
	rMod := statMtime(e.routesPath)

	if !initial && wMod.Equal(e.whiteMtime) && bMod.Equal(e.blockMtime) && rMod.Equal(e.routeMtime) {
		return
	}
	e.whiteMtime = wMod
	e.blockMtime = bMod
	e.routeMtime = rMod

	sn := &aclSnapshot{
		whitelist: newCompiledRule("whitelist", ActionDirect),
		blocklist: newCompiledRule("blocklist", ActionBlock),
	}

	if lines, err := readRuleLines(e.whitePath); err == nil {
		for _, l := range lines {
			sn.whitelist.addPattern(l)
		}
	}
	if lines, err := readRuleLines(e.blockPath); err == nil {
		for _, l := range lines {
			sn.blocklist.addPattern(l)
		}
	}
	if fileRoutes := ParseRoutesTOML(e.routesPath); len(fileRoutes) > 0 {
		sn.routes = append(sn.routes, fileRoutes...)
	}
	for _, pr := range e.panelRoutes {
		act := strings.ToLower(strings.TrimSpace(pr.Action))
		var cr compiledRule
		switch act {
		case "block":
			cr = newCompiledRule("panel-block", ActionBlock)
		case "proxy", "socks5", "http", "ss", "trojan", "vless", "direct":
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
	if !initial {
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
	if e != nil && e.IsPortForbidden(destPort) {
		return OutboundTarget{Action: ActionBlock, RuleName: "forbidden-port", MatchedRule: true}
	}
	if e != nil && e.banPrivateIP {
		if ip, err := netip.ParseAddr(destHost); err == nil {
			ip = ip.Unmap()
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				return OutboundTarget{Action: ActionBlock, RuleName: "ban-private-ip", MatchedRule: true}
			}
		}
	}
	return e.Decide(destHost, sniffDomain, sniffProto)
}

// Decide evaluates target host/IP and sniffed protocol/domain, returning the outbound action.
func (e *Engine) Decide(destHost string, sniffDomain string, sniffProto string) OutboundTarget {
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

	if sn.whitelist.matches(host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionDirect, RuleName: "whitelist", MatchedRule: true}
	}
	if sn.blocklist.matches(host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionBlock, RuleName: "blocklist", MatchedRule: true}
	}
	for i := range sn.routes {
		if sn.routes[i].matches(host, sdom, ip, sniffProto) {
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
		protocols:    make(map[string]struct{}),
		action:       act,
	}
}

func (r *compiledRule) addPattern(raw string) {
	p := strings.TrimSpace(raw)
	if p == "" || strings.HasPrefix(p, "#") {
		return
	}
	if p == "*" || strings.EqualFold(p, "all") || strings.EqualFold(p, "any") {
		// Match any domain or IPv4/IPv6 prefix
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
	if strings.HasPrefix(p, "protocol:") {
		r.protocols[strings.ToLower(strings.TrimSpace(p[9:]))] = struct{}{}
		return
	}
	if strings.EqualFold(p, "bittorrent") {
		r.protocols["bittorrent"] = struct{}{}
		return
	}
	if strings.HasPrefix(p, "full:") {
		r.exactDomains[strings.ToLower(strings.TrimSpace(p[5:]))] = struct{}{}
		return
	}
	if strings.HasPrefix(p, "domain:") {
		s := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(p[7:]), "."))
		if s != "" {
			r.suffixes = append(r.suffixes, s)
		}
		return
	}
	if strings.HasPrefix(p, "keyword:") {
		k := strings.ToLower(strings.TrimSpace(p[8:]))
		if k != "" {
			r.keywords = append(r.keywords, k)
		}
		return
	}
	if strings.HasPrefix(p, "regexp:") {
		if re, err := regexp.Compile(strings.TrimSpace(p[7:])); err == nil {
			r.regexps = append(r.regexps, re)
		}
		return
	}
	if pfx, err := netip.ParsePrefix(p); err == nil {
		r.prefixes = append(r.prefixes, pfx.Masked())
		return
	}
	if addr, err := netip.ParseAddr(p); err == nil {
		addr = addr.Unmap()
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		r.prefixes = append(r.prefixes, netip.PrefixFrom(addr, bits))
		return
	}
	s := strings.ToLower(strings.TrimPrefix(p, "*."))
	s = strings.TrimPrefix(s, ".")
	if s != "" {
		r.suffixes = append(r.suffixes, s)
	}
}

func (r *compiledRule) matches(host, sdom string, ip netip.Addr, proto string) bool {
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

func (r *compiledRule) matchDomain(d string) bool {
	if _, ok := r.exactDomains[d]; ok {
		return true
	}
	for _, suf := range r.suffixes {
		if d == suf || (len(d) > len(suf) && strings.HasSuffix(d, suf) && d[len(d)-len(suf)-1] == '.') {
			return true
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

func statMtime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
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
				node.Cipher = usr
				node.Password = pw
			} else {
				node.Cipher = firstNonEmpty(q.Get("method"), "aes-256-gcm")
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
	if path == "" {
		return nil
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Coalesce multi-line `[ ... ]` arrays into single lines for clean zero-dependency TOML parsing
	lines := coalesceMultilineArrays(string(rawBytes))

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
			continue
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
			switch k {
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
			case "outboundTag", "outbound_tag":
				d.outTag = unquoted
			case "rules", "match", "domain", "domains", "ip":
				d.matches = append(d.matches, parseTOMLStringArray(v)...)
			}
		case "route_out":
			d := &drafts[len(drafts)-1]
			out := &d.outs[len(d.outs)-1]
			applyOutboundKV(out, k, unquoted)
		case "named_out":
			if k == "tag" || k == "name" {
				curNamedTag = unquoted
			} else {
				applyOutboundKV(&curNamedNode, k, unquoted)
			}
		}
	}
	flushNamed()
	if !fileEnabled {
		return nil
	}

	var compiled []compiledRule
	for i, d := range drafts {
		if !d.enable || len(d.matches) == 0 {
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
			act = ActionBlock
		}

		cr := newCompiledRule(name, act)
		cr.balance = d.balance
		cr.outs = d.outs
		for _, m := range d.matches {
			cr.addPattern(m)
		}
		compiled = append(compiled, cr)
	}
	return compiled
}

func applyOutboundKV(out *OutboundNode, k, v string) {
	switch k {
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
	var out []string
	var buf strings.Builder
	bracketDepth := 0

	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(stripTOMLComment(sc.Text()))
		if line == "" {
			continue
		}
		if bracketDepth > 0 {
			buf.WriteByte(' ')
			buf.WriteString(line)
			bracketDepth += countBrackets(line)
			if bracketDepth <= 0 {
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
		out = append(out, line)
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

func countBrackets(s string) int {
	inQ := byte(0)
	d := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			if c == inQ && (i == 0 || s[i-1] != '\\') {
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
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQ != 0 {
			if c == inQ && (i == 0 || s[i-1] != '\\') {
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

func parseTOMLStringArray(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.Trim(strings.TrimSpace(item), "\"'")
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
