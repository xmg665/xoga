package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

type cachedDetectEntry struct {
	rules   []string
	expires int64
}

var (
	detectCacheMu sync.RWMutex
	detectCache   = make(map[string]cachedDetectEntry)
)

// SSPanelClient implements SSPanel-UIM and SSPanel-Metron `/mod_mu/*` WebAPI endpoints.
type SSPanelClient struct {
	cfg     *config.Config
	http    *http.Client
	baseURL string

	mu              sync.Mutex
	nodeETag        string
	usersETag       string
	lastUsersHash   [32]byte
	hasUsersHash    bool
	lastUsersLen    atomic.Int64
	nodeSpeed       float64
	nodeConn        int
	nodeRate        float64
	lastDetectRules []string
	lastNodeBody    []byte
}

func NewSSPanelClient(cfg *config.Config, httpCli *http.Client) *SSPanelClient {
	return &SSPanelClient{
		cfg:      cfg,
		http:     httpCli,
		baseURL:  strings.TrimRight(cfg.WebAPIURL, "/"),
		nodeRate: 1.0,
	}
}

func (c *SSPanelClient) Name() string {
	return "SSPanel(mod_mu)"
}

func (c *SSPanelClient) ClearNodeConfigETag() {
	c.mu.Lock()
	c.nodeETag = ""
	c.mu.Unlock()
}

func (c *SSPanelClient) modURL(path string, includeNodeID bool) string {
	q := url.Values{}
	q.Set("key", c.cfg.WebAPIKey)
	if includeNodeID {
		q.Set("node_id", strconv.Itoa(c.cfg.NodeID))
	}
	return c.baseURL + path + "?" + q.Encode()
}

type sspanelNodeResp struct {
	Ret  int `json:"ret"`
	Data struct {
		NodeSpeedlimit float64         `json:"node_speedlimit"`
		NodeConnector  int             `json:"node_connector"`
		TrafficRate    *float64        `json:"traffic_rate"`
		Server         string          `json:"server"`
		Method         string          `json:"method"`
		Sort           *int            `json:"sort"`
		CustomConfig   json.RawMessage `json:"custom_config"`
	} `json:"data"`
}

// sspanelProtocolFromSort maps SSPanel-UIM / Metron / Malio `sort` codes directly to xoga inbound protocols
// so nodes automatically inherit their protocol from the panel (even in mixed-protocol multi-node instances).
func sspanelProtocolFromSort(sortPtr *int, method string, cfg *config.Config) string {
	fb := cfg.NormalizedServerType()
	if fb == "" || fb == "auto" {
		fb = "vmess"
	}
	if sortPtr == nil {
		return fb
	}
	switch *sortPtr {
	case 0, 9, 10:
		return "shadowsocks"
	case 11, 12:
		if cfg.VLESS || cfg.IsRealityConfigured() {
			return "vless"
		}
		return "vmess"
	case 13:
		if method != "" && !strings.EqualFold(method, "none") {
			return "shadowsocks"
		}
		return "vless"
	case 14:
		return "trojan"
	case 15:
		return "hysteria2"
	case 16, 17, 19, 20:
		return "anytls"
	case 18:
		return "vless"
	default:
		return fb
	}
}

func (c *SSPanelClient) FetchNodeConfig(ctx context.Context) (*NodeSpec, error) {
	c.mu.Lock()
	etag := c.nodeETag
	c.mu.Unlock()

	u := c.modURL(fmt.Sprintf("/mod_mu/nodes/%d/info", c.cfg.NodeID), false)
	body, newETag, status, err := c.doGet(ctx, u, etag)
	if errors.Is(err, ErrNotModified) {
		// Even when node info returns 304, check if cached dynamic detect_rules expired and changed!
		rules, changed := c.checkDetectRulesChanged(ctx)
		if !changed {
			return nil, ErrNotModified
		}
		c.mu.Lock()
		body = append([]byte(nil), c.lastNodeBody...)
		c.mu.Unlock()
		if len(body) == 0 {
			return nil, ErrNotModified
		}
		_ = rules
	} else if err != nil {
		return nil, fmt.Errorf("fetch SSPanel node info (HTTP %d): %w", status, err)
	}

	var resp sspanelNodeResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode SSPanel node info: %w (body: %s)", err, truncateMsg(body))
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("SSPanel node info returned ret=%d", resp.Ret)
	}

	rate := 1.0
	if resp.Data.TrafficRate != nil && *resp.Data.TrafficRate >= 0 {
		rate = *resp.Data.TrafficRate
	}
	c.mu.Lock()
	if newETag != "" {
		c.nodeETag = newETag
	}
	c.lastNodeBody = append(c.lastNodeBody[:0], body...)
	if c.nodeSpeed != resp.Data.NodeSpeedlimit || c.nodeConn != resp.Data.NodeConnector || c.nodeRate != rate {
		c.usersETag = ""
		c.hasUsersHash = false
	}
	c.nodeSpeed = resp.Data.NodeSpeedlimit
	c.nodeConn = resp.Data.NodeConnector
	c.nodeRate = rate
	c.mu.Unlock()

	spec := &NodeSpec{
		Protocol: sspanelProtocolFromSort(resp.Data.Sort, resp.Data.Method, c.cfg),
		ListenIP: "0.0.0.0",
		Network:  "tcp",
		Cipher:   strings.ToLower(strings.TrimSpace(resp.Data.Method)),
	}
	if spec.Cipher == "" || spec.Cipher == "none" {
		spec.Cipher = "aes-256-gcm"
	}

	// Parse SSPanel-UIM / Metron semicolon & pipe-delimited server string:
	// e.g. "hk5.v2api.xyz;2001;0;ws;;path=/mm|server=news2.help600.com|host=aomen.kugou.com|outside_port=20001"
	parseMetronServerString(resp.Data.Server, spec)

	// Override with SSPanel-UIM structured custom_config JSON when present
	if len(resp.Data.CustomConfig) > 2 && string(resp.Data.CustomConfig) != "[]" {
		var cc map[string]any
		if json.Unmarshal(resp.Data.CustomConfig, &cc) == nil {
			if v := parseAnyInt(cc["offset_port_node"]); v > 0 {
				spec.ServerPort = v
			} else if v := parseAnyInt(cc["server_port"]); v > 0 {
				spec.ServerPort = v
			} else if v := parseAnyInt(cc["mu_port"]); v > 0 && spec.ServerPort == 0 {
				spec.ServerPort = v
			}
			if s, ok := cc["network"].(string); ok && s != "" {
				spec.Network = strings.ToLower(s)
			}
			if s, ok := cc["method"].(string); ok && s != "" {
				spec.Cipher = strings.ToLower(s)
			}
			if s, ok := cc["server_key"].(string); ok && s != "" {
				spec.ServerKey = s
			}
			if s, ok := cc["path"].(string); ok && s != "" {
				spec.WSPath = s
			}
			if s, ok := cc["host"].(string); ok && s != "" {
				spec.WSHost = s
				if spec.ServerName == "" {
					spec.ServerName = s
				}
			}
			if s, ok := cc["sni"].(string); ok && s != "" {
				spec.ServerName = s
			}
			if parseAnyInt(cc["security"]) == 2 || cc["security"] == "reality" || cc["reality"] == "1" || cc["reality"] == true || parseAnyInt(cc["reality"]) == 1 {
				spec.TLSMode = 2
			} else if parseAnyInt(cc["security"]) > 0 || cc["security"] == "tls" || cc["tls"] == "1" || cc["tls"] == true || parseAnyInt(cc["tls"]) > 0 {
				spec.TLSMode = 1
			}
			if pStr, ok := cc["protocol"].(string); ok {
				if np := normalizePanelProtoName(pStr); np != "" {
					spec.Protocol = np
				}
			} else if tStr, ok := cc["type"].(string); ok {
				if np := normalizePanelProtoName(tStr); np != "" {
					spec.Protocol = np
				}
			}
			if cc["enable_vless"] == "1" || cc["enable_vless"] == true || parseAnyInt(cc["enable_vless"]) == 1 || cc["vless"] == "1" || cc["vless"] == true || parseAnyInt(cc["vless"]) == 1 {
				spec.Protocol = "vless"
			}
			if s, ok := cc["flow"].(string); ok && s != "" {
				spec.Flow = s
			}
			if s, ok := cc["private_key"].(string); ok && s != "" {
				spec.RealityPrivateKey = strings.TrimSpace(s)
			}
			if s, ok := cc["dest"].(string); ok && s != "" {
				spec.RealityDest = strings.TrimSpace(s)
			} else if s, ok := cc["reality_dest"].(string); ok && s != "" {
				spec.RealityDest = strings.TrimSpace(s)
			}
			if s, ok := cc["short_id"].(string); ok && s != "" {
				for _, sid := range strings.Split(s, ",") {
					spec.RealityShortIDs = append(spec.RealityShortIDs, strings.TrimSpace(sid))
				}
			}
			if arr, ok := cc["short_ids"].([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok {
						spec.RealityShortIDs = append(spec.RealityShortIDs, strings.TrimSpace(s))
					}
				}
			}
			if arr, ok := cc["server_names"].([]any); ok {
				for _, it := range arr {
					if s, ok := it.(string); ok && strings.TrimSpace(s) != "" {
						spec.RealityServerNames = append(spec.RealityServerNames, strings.TrimSpace(s))
					}
				}
			}
			if s, ok := cc["obfs"].(string); ok && s != "" {
				spec.Hy2Obfs = strings.ToLower(strings.TrimSpace(s))
			}
			if s, ok := cc["obfs_password"].(string); ok && s != "" {
				spec.Hy2ObfsPassword = strings.TrimSpace(s)
			}
			if v := parseAnyInt(cc["up_mbps"]); v > 0 {
				spec.Hy2UpMbps = v
			}
			if v := parseAnyInt(cc["down_mbps"]); v > 0 {
				spec.Hy2DownMbps = v
			}
			if s, ok := cc["padding_scheme"].(string); ok && s != "" {
				spec.AnyTLSPaddingScheme = s
			}
		}
	}

	applyConfigProtocolOverrides(c.cfg, spec)
	if spec.RealityPrivateKey != "" || c.cfg.IsRealityConfigured() {
		spec.TLSMode = 2
		if spec.RealityDest == "" && spec.ServerName != "" {
			spec.RealityDest = net.JoinHostPort(spec.ServerName, "443")
		}
		if len(spec.RealityServerNames) == 0 && spec.ServerName != "" {
			spec.RealityServerNames = []string{spec.ServerName}
		}
	}
	if spec.Protocol == "hysteria2" {
		if spec.Network == "" || spec.Network == "tcp" {
			spec.Network = "quic"
		}
		if spec.TLSMode == 0 {
			spec.TLSMode = 1
		}
	} else if spec.Protocol == "anytls" && spec.TLSMode == 0 {
		spec.TLSMode = 1
	}

	// Local `listen_port` override in xoga.conf always takes final precedence when > 0
	if c.cfg.ListenPort > 0 {
		spec.ServerPort = c.cfg.ListenPort
	}

	// Optionally pull SSPanel-UIM dynamic audit rules (`/mod_mu/func/detect_rules`)
	rules := c.fetchDetectRules(ctx)
	if len(rules) > 0 {
		spec.Routes = append(spec.Routes, acl.DynamicRoute{
			Matches: rules,
			Action:  "block",
		})
	}

	chk := sha256.New()
	_, _ = chk.Write(body)
	for _, r := range rules {
		_, _ = chk.Write([]byte{0})
		_, _ = chk.Write([]byte(r))
	}
	sum := chk.Sum(nil)
	spec.ConfigChecksum = hex.EncodeToString(sum[:16])
	return spec, nil
}

func (c *SSPanelClient) checkDetectRulesChanged(ctx context.Context) ([]string, bool) {
	cacheKey := fmt.Sprintf("%s|%s|%d", c.baseURL, c.cfg.WebAPIKey, c.cfg.NodeID)
	now := time.Now().Unix()
	detectCacheMu.RLock()
	_, fresh := detectCache[cacheKey]
	if fresh && detectCache[cacheKey].expires > now {
		detectCacheMu.RUnlock()
		return nil, false
	}
	detectCacheMu.RUnlock()

	c.mu.Lock()
	prev := append([]string(nil), c.lastDetectRules...)
	c.mu.Unlock()

	cur := c.fetchDetectRules(ctx)
	if len(cur) != len(prev) {
		return cur, true
	}
	for i := range cur {
		if cur[i] != prev[i] {
			return cur, true
		}
	}
	return cur, false
}

func (c *SSPanelClient) fetchDetectRules(ctx context.Context) []string {
	cacheKey := fmt.Sprintf("%s|%s|%d", c.baseURL, c.cfg.WebAPIKey, c.cfg.NodeID)
	now := time.Now().Unix()

	detectCacheMu.RLock()
	if ce, ok := detectCache[cacheKey]; ok && ce.expires > now {
		rules := ce.rules
		detectCacheMu.RUnlock()
		return rules
	}
	detectCacheMu.RUnlock()

	fallback := func() []string {
		c.mu.Lock()
		defer c.mu.Unlock()
		return append([]string(nil), c.lastDetectRules...)
	}

	body, _, status, err := c.doGet(ctx, c.modURL("/mod_mu/func/detect_rules", true), "")
	if err != nil {
		if status == http.StatusNotFound {
			return nil
		}
		return fallback()
	}
	var resp struct {
		Ret  int `json:"ret"`
		Data []struct {
			Regex string `json:"regex"`
			Type  int    `json:"type"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp) != nil || resp.Ret != 1 {
		return fallback()
	}
	var out []string
	for _, r := range resp.Data {
		if r.Regex != "" {
			out = append(out, "regexp:"+r.Regex)
		}
	}

	c.mu.Lock()
	c.lastDetectRules = append([]string(nil), out...)
	c.mu.Unlock()

	detectCacheMu.Lock()
	detectCache[cacheKey] = cachedDetectEntry{
		rules:   out,
		expires: now + 300,
	}
	detectCacheMu.Unlock()
	return out
}

func parseMetronServerString(srv string, spec *NodeSpec) {
	if srv == "" {
		return
	}
	var firstHost string
	parts := strings.Split(srv, ";")
	for i, rawPart := range parts {
		rawPart = strings.TrimSpace(rawPart)
		if rawPart == "" {
			continue
		}
		if i == 0 {
			hostPart := rawPart
			// Sometimes host:port#listenPort
			if idx := strings.IndexByte(rawPart, '#'); idx > 0 {
				hostPart = rawPart[:idx]
				if p, err := strconv.Atoi(rawPart[idx+1:]); err == nil && p > 0 {
					spec.ServerPort = p
				}
			}
			if hOnly, portStr, hasColon := strings.Cut(hostPart, ":"); hasColon {
				hostPart = hOnly
				if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && spec.ServerPort == 0 {
					spec.ServerPort = p
				}
			}
			firstHost = strings.TrimSpace(hostPart)
			continue
		}

		// SSPanel-UIM V2Ray/Trojan strings pack pipe-separated `k1=v1|k2=v2` inside semicolon fields:
		// e.g. `hk5.v2api.xyz;2001;0;ws;;path=/mm|server=news2.help600.com|host=aomen.kugou.com|outside_port=20001`
		for _, sub := range strings.Split(rawPart, "|") {
			part := strings.TrimSpace(sub)
			if part == "" {
				continue
			}
			lower := strings.ToLower(part)
			switch lower {
			case "ws":
				spec.Network = "ws"
			case "tcp":
				spec.Network = "tcp"
			case "tls":
				spec.TLSMode = 1
			case "vless":
				spec.Protocol = "vless"
			default:
				k, v, ok := strings.Cut(part, "=")
				if !ok {
					// Positional port at index 1 (`addr;2001;0;ws;...`); ignore index 2 (`alterId`)
					if i == 1 && spec.ServerPort == 0 {
						if p, err := strconv.Atoi(part); err == nil && p > 0 {
							spec.ServerPort = p
						}
					}
					continue
				}
				v = strings.TrimSpace(v)
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "port":
					if _, right, hasHash := strings.Cut(v, "#"); hasHash {
						if p, err := strconv.Atoi(right); err == nil && p > 0 {
							spec.ServerPort = p
						}
					} else if p, err := strconv.Atoi(v); err == nil && p > 0 {
						spec.ServerPort = p
					}
				case "server_port", "inside_port", "offset_port_node":
					if p, err := strconv.Atoi(v); err == nil && p > 0 {
						spec.ServerPort = p
					}
				case "path":
					spec.WSPath = v
				case "host", "sni", "peer":
					spec.WSHost = v
					if spec.ServerName == "" {
						spec.ServerName = v
					}
				case "net", "network":
					spec.Network = strings.ToLower(v)
				case "tls", "security":
					if v == "2" || strings.EqualFold(v, "reality") {
						spec.TLSMode = 2
					} else if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "tls") {
						spec.TLSMode = 1
					}
				case "vless", "enable_vless":
					if v == "1" || strings.EqualFold(v, "true") {
						spec.Protocol = "vless"
					}
				case "flow":
					spec.Flow = v
				case "private_key", "privatekey":
					spec.RealityPrivateKey = v
				case "short_id", "shortid", "sid":
					for _, sid := range strings.Split(v, ",") {
						if s := strings.TrimSpace(sid); s != "" {
							spec.RealityShortIDs = append(spec.RealityShortIDs, s)
						}
					}
				case "dest", "reality_dest":
					spec.RealityDest = v
				case "servername", "server_name":
					spec.ServerName = v
				case "obfs":
					spec.Hy2Obfs = strings.ToLower(v)
				case "obfs_password", "obfs-password":
					spec.Hy2ObfsPassword = v
				case "up_mbps", "up":
					spec.Hy2UpMbps, _ = strconv.Atoi(v)
				case "down_mbps", "down":
					spec.Hy2DownMbps, _ = strconv.Atoi(v)
				case "server_key":
					spec.ServerKey = v
				}
			}
		}
	}
	if spec.ServerName == "" && firstHost != "" && net.ParseIP(firstHost) == nil {
		spec.ServerName = firstHost
	}
}

type sspanelUsersResp struct {
	Ret  int `json:"ret"`
	Data []struct {
		ID             int    `json:"id"`
		UUID           string `json:"uuid"`
		Passwd         string `json:"passwd"`
		Enable         *int   `json:"enable"`
		U              int64  `json:"u"`
		D              int64  `json:"d"`
		TransferEnable int64  `json:"transfer_enable"`
		NodeSpeedlimit any    `json:"node_speedlimit"`
		NodeConnector  any    `json:"node_connector"`
		V2rayUser      *struct {
			UUID string `json:"uuid"`
		} `json:"v2ray_user"`
	} `json:"data"`
}

func parseAnyFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	default:
		return 0
	}
}

func (c *SSPanelClient) FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error) {
	c.mu.Lock()
	etag := c.usersETag
	prevHash := c.lastUsersHash
	hasPrevHash := c.hasUsersHash
	nodeSpeed := c.nodeSpeed
	nodeConn := c.nodeConn
	nodeRate := c.nodeRate
	c.mu.Unlock()

	u := c.modURL("/mod_mu/users", true)
	body, newETag, status, err := c.doGet(ctx, u, etag)
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch SSPanel users (HTTP %d): %w", status, err)
	}

	// Fast body-hash short-circuit: SSPanel PHP endpoints rarely emit HTTP `ETag`,
	// so comparing SHA-256 skips `json.Unmarshal` (5,000+ structs) & `ReconcileUsers` when unchanged!
	bodyHash := sha256.Sum256(body)
	if hasPrevHash && bodyHash == prevHash {
		return nil, ErrNotModified
	}

	var resp sspanelUsersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode SSPanel users: %w (body: %s)", err, truncateMsg(body))
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("SSPanel users returned ret=%d", resp.Ret)
	}
	c.mu.Lock()
	c.lastUsersHash = bodyHash
	c.hasUsersHash = true
	if newETag != "" {
		c.usersETag = newETag
	}
	c.mu.Unlock()

	out := make([]stats.SyncUserSpec, 0, len(resp.Data))
	for _, item := range resp.Data {
		if item.Enable != nil && *item.Enable == 0 {
			continue
		}
		var remain int64 = -1
		if item.TransferEnable > 0 {
			rawRemain := item.TransferEnable - (item.U + item.D)
			if rawRemain <= 0 {
				continue
			}
			if nodeRate == 0 {
				// 0x free-traffic node: allowed while user has positive panel balance, without burning quota locally
				remain = -1
			} else if nodeRate > 0 {
				scaled := float64(rawRemain) / nodeRate
				if scaled >= float64(1<<60) {
					remain = 1 << 60
				} else {
					remain = int64(scaled)
					if remain <= 0 {
						remain = 1
					}
				}
			}
		}
		uuid := strings.TrimSpace(item.UUID)
		if uuid == "" && item.V2rayUser != nil {
			uuid = strings.TrimSpace(item.V2rayUser.UUID)
		}
		passwd := strings.TrimSpace(item.Passwd)
		// Preserve `UUID` in `UUIDOrPass` and `Passwd` in `AltPasswd` consistently so:
		// - VLESS/VMess use `u.UUID`
		// - Shadowsocks uses `u.Passwd` (never overwritten by UUID!)
		// - Trojan/AnyTLS/Hysteria2 accept both `u.Passwd` and `u.UUID`
		cred := uuid
		altPass := passwd
		if cred == "" {
			cred = passwd
			altPass = ""
		} else if altPass == cred {
			altPass = ""
		}
		if item.ID <= 0 || cred == "" {
			continue
		}
		mbps := parseAnyFloat(item.NodeSpeedlimit)
		if nodeSpeed > 0 && (mbps <= 0 || nodeSpeed < mbps) {
			mbps = nodeSpeed
		}
		dev := parseAnyInt(item.NodeConnector)
		if nodeConn > 0 && (dev <= 0 || nodeConn < dev) {
			dev = nodeConn
		}
		out = append(out, stats.SyncUserSpec{
			ID:          item.ID,
			UUIDOrPass:  cred,
			AltPasswd:   altPass,
			SpeedLimit:  int64(mbps * 125000.0),
			DeviceLimit: dev,
			RemainBytes: remain,
		})
	}
	return out, nil
}

func (c *SSPanelClient) FetchAliveList(_ context.Context) (*AliveList, error) {
	return nil, nil
}

func (c *SSPanelClient) PushTraffic(ctx context.Context, batch []stats.TrafficDelta) error {
	if len(batch) == 0 {
		return nil
	}
	type row struct {
		UserID int   `json:"user_id"`
		U      int64 `json:"u"`
		D      int64 `json:"d"`
	}
	rows := make([]row, 0, len(batch))
	for _, b := range batch {
		rows = append(rows, row{UserID: b.UserID, U: b.Upload, D: b.Download})
	}
	return c.doPost(ctx, c.modURL("/mod_mu/users/traffic", true), map[string]any{"data": rows})
}

func (c *SSPanelClient) PushAlive(ctx context.Context, alive map[int][]string) error {
	if len(alive) == 0 {
		return nil
	}
	type ipRow struct {
		IP     string `json:"ip"`
		UserID int    `json:"userid"`
	}
	var rows []ipRow
	for uid, ips := range alive {
		for _, ip := range ips {
			rows = append(rows, ipRow{IP: ip, UserID: uid})
		}
	}
	if len(rows) == 0 {
		return nil
	}
	return c.doPost(ctx, c.modURL("/mod_mu/users/aliveip", true), map[string]any{"data": rows})
}

func (c *SSPanelClient) PushStatus(ctx context.Context, st SystemStatus) error {
	loadStr := st.LoadAvg
	if loadStr == "" {
		loadStr = fmt.Sprintf("%.2f %.2f %.2f", st.CPU/100.0, st.CPU/100.0, st.CPU/100.0)
	}
	u := c.modURL(fmt.Sprintf("/mod_mu/nodes/%d/info", c.cfg.NodeID), false)
	return c.doPost(ctx, u, map[string]any{
		"load":   loadStr,
		"uptime": strconv.FormatUint(st.UptimeSec, 10),
	})
}

func (c *SSPanelClient) doGet(ctx context.Context, fullURL, ifNoneMatch string) ([]byte, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", "xoga/1.0")
	req.Header.Set("Accept", "application/json")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", 0, redactErr(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ifNoneMatch, http.StatusNotModified, ErrNotModified
	}
	body, err := readResponseBody(resp, &c.lastUsersLen)
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return body, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func readResponseBody(resp *http.Response, sizeHint *atomic.Int64) ([]byte, error) {
	const maxBody = 32 * 1024 * 1024
	lr := io.LimitReader(resp.Body, maxBody)
	initCap := 0
	hint := int64(0)
	if sizeHint != nil {
		hint = sizeHint.Load()
	}
	if resp.ContentLength > 0 && resp.ContentLength <= maxBody {
		initCap = int(resp.ContentLength) + 64
	} else if hint > 4096 && hint <= maxBody {
		initCap = int(hint) + 4096
	}
	if initCap > 0 {
		var buf bytes.Buffer
		buf.Grow(initCap)
		if _, err := buf.ReadFrom(lr); err != nil {
			return nil, err
		}
		b := buf.Bytes()
		if sizeHint != nil && len(b) > 4096 {
			sizeHint.Store(int64(len(b)))
		}
		return b, nil
	}
	b, err := io.ReadAll(lr)
	if err == nil && sizeHint != nil && len(b) > 4096 {
		sizeHint.Store(int64(len(b)))
	}
	return b, err
}

func (c *SSPanelClient) doPost(ctx context.Context, fullURL string, v any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "xoga/1.0")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return redactErr(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return nil
}
