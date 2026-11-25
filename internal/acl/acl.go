package acl

import (
	"bufio"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type Action uint8

const (
	ActionDirect Action = iota
	ActionBlock
	ActionProxy
)

// OutboundTarget specifies a custom outbound proxy from routes.toml or panel route action.
type OutboundTarget struct {
	Action  Action
	Address string // e.g., socks5://127.0.0.1:1080 or http://127.0.0.1:8080
}

type compiledRule struct {
	exactDomains map[string]struct{}
	suffixes     []string
	keywords     []string
	regexps      []*regexp.Regexp
	prefixes     []netip.Prefix
	protocols    map[string]struct{}
	target       OutboundTarget
}

// Engine evaluates whitelist, blocklist, BitTorrent policy, and panel/local route rules
// with zero GeoIP/GeoSite protobuf heap bloat.
type Engine struct {
	forbidBT  bool
	whitelist compiledRule
	blocklist compiledRule
	routes    []compiledRule
}

type DynamicRoute struct {
	Matches     []string
	Action      string // "block", "dns", "direct", "proxy", "default_out"
	ActionValue string
}

func NewEngine(forbidBT bool, whitePath, blockPath, routesPath string, panelRoutes []DynamicRoute) *Engine {
	e := &Engine{
		forbidBT:  forbidBT,
		whitelist: newCompiledRule(OutboundTarget{Action: ActionDirect}),
		blocklist: newCompiledRule(OutboundTarget{Action: ActionBlock}),
	}
	if lines, err := readRuleLines(whitePath); err == nil {
		for _, l := range lines {
			e.whitelist.addPattern(l)
		}
	}
	if lines, err := readRuleLines(blockPath); err == nil {
		for _, l := range lines {
			e.blocklist.addPattern(l)
		}
	}
	if fileRoutes := parseRoutesTOML(routesPath); len(fileRoutes) > 0 {
		e.routes = append(e.routes, fileRoutes...)
	}
	for _, pr := range panelRoutes {
		act := strings.ToLower(strings.TrimSpace(pr.Action))
		var target OutboundTarget
		switch act {
		case "block":
			target = OutboundTarget{Action: ActionBlock}
		case "proxy", "socks5", "http":
			target = OutboundTarget{Action: ActionProxy, Address: strings.TrimSpace(pr.ActionValue)}
		default:
			continue
		}
		cr := newCompiledRule(target)
		for _, m := range pr.Matches {
			cr.addPattern(m)
		}
		e.routes = append(e.routes, cr)
	}
	return e
}

// Decide evaluates target host/IP and sniffed protocol/domain, returning the outbound action.
func (e *Engine) Decide(destHost string, sniffDomain string, sniffProto string) OutboundTarget {
	if e == nil {
		return OutboundTarget{Action: ActionDirect}
	}
	if e.forbidBT && sniffProto == "bittorrent" {
		return OutboundTarget{Action: ActionBlock}
	}

	var ip netip.Addr
	if parsed, err := netip.ParseAddr(destHost); err == nil {
		ip = parsed.Unmap()
	}

	host := strings.ToLower(strings.TrimSuffix(destHost, "."))
	sdom := strings.ToLower(strings.TrimSuffix(sniffDomain, "."))

	if e.whitelist.matches(host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionDirect}
	}
	if e.blocklist.matches(host, sdom, ip, sniffProto) {
		return OutboundTarget{Action: ActionBlock}
	}
	for i := range e.routes {
		if e.routes[i].matches(host, sdom, ip, sniffProto) {
			return e.routes[i].target
		}
	}
	return OutboundTarget{Action: ActionDirect}
}

func newCompiledRule(t OutboundTarget) compiledRule {
	return compiledRule{
		exactDomains: make(map[string]struct{}),
		protocols:    make(map[string]struct{}),
		target:       t,
	}
}

func (r *compiledRule) addPattern(raw string) {
	p := strings.TrimSpace(raw)
	if p == "" || strings.HasPrefix(p, "#") {
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
	// CIDR or single IP
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
	// Default: domain suffix match (compatible with soga blockList / V2Board routes)
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

// parseRoutesTOML parses minimal [[routes]] sections from routes.toml without pulling in a TOML dependency.
func parseRoutesTOML(path string) []compiledRule {
	lines, err := readRuleLines(path)
	if err != nil {
		return nil
	}
	var rules []compiledRule
	var curMatches []string
	var curAction, curOut string
	flush := func() {
		if len(curMatches) == 0 {
			return
		}
		var t OutboundTarget
		switch strings.ToLower(curAction) {
		case "block":
			t = OutboundTarget{Action: ActionBlock}
		case "proxy", "outbound":
			t = OutboundTarget{Action: ActionProxy, Address: curOut}
		case "direct":
			t = OutboundTarget{Action: ActionDirect}
		default:
			if curOut != "" {
				t = OutboundTarget{Action: ActionProxy, Address: curOut}
			} else {
				t = OutboundTarget{Action: ActionBlock}
			}
		}
		cr := newCompiledRule(t)
		for _, m := range curMatches {
			cr.addPattern(m)
		}
		rules = append(rules, cr)
		curMatches = nil
		curAction = ""
		curOut = ""
	}

	for _, l := range lines {
		if l == "[[routes]]" || l == "[route]" {
			flush()
			continue
		}
		eq := strings.IndexByte(l, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(l[:eq])
		v := strings.TrimSpace(l[eq+1:])
		v = strings.Trim(v, "\"'")
		switch k {
		case "action", "type":
			curAction = v
		case "outbound", "address", "proxy", "server":
			curOut = v
		case "match", "rule", "rules":
			v = strings.Trim(v, "[]")
			for _, item := range strings.Split(v, ",") {
				item = strings.Trim(strings.TrimSpace(item), "\"'")
				if item != "" {
					curMatches = append(curMatches, item)
				}
			}
		}
	}
	flush()
	return rules
}
