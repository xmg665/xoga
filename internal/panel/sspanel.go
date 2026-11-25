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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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

	mu        sync.Mutex
	nodeETag  string
	usersETag string
	nodeSpeed float64
	nodeConn  int
}

func NewSSPanelClient(cfg *config.Config, httpCli *http.Client) *SSPanelClient {
	return &SSPanelClient{
		cfg:     cfg,
		http:    httpCli,
		baseURL: strings.TrimRight(cfg.WebAPIURL, "/"),
	}
}

func (c *SSPanelClient) Name() string {
	return "SSPanel(mod_mu)"
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
		Server         string          `json:"server"`
		Method         string          `json:"method"`
		Sort           int             `json:"sort"`
		CustomConfig   json.RawMessage `json:"custom_config"`
	} `json:"data"`
}

func (c *SSPanelClient) FetchNodeConfig(ctx context.Context) (*NodeSpec, error) {
	c.mu.Lock()
	etag := c.nodeETag
	c.mu.Unlock()

	u := c.modURL(fmt.Sprintf("/mod_mu/nodes/%d/info", c.cfg.NodeID), false)
	body, newETag, status, err := c.doGet(ctx, u, etag)
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch SSPanel node info (HTTP %d): %w", status, err)
	}

	var resp sspanelNodeResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode SSPanel node info: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("SSPanel node info returned ret=%d", resp.Ret)
	}

	c.mu.Lock()
	if newETag != "" {
		c.nodeETag = newETag
	}
	c.nodeSpeed = resp.Data.NodeSpeedlimit
	c.nodeConn = resp.Data.NodeConnector
	c.mu.Unlock()

	spec := &NodeSpec{
		Protocol:   c.cfg.NormalizedServerType(),
		ListenIP:   "0.0.0.0",
		Network:    "tcp",
		Cipher:     strings.ToLower(resp.Data.Method),
		ServerPort: c.cfg.ListenPort,
	}
	if spec.Cipher == "" {
		spec.Cipher = "aes-256-gcm"
	}

	// Parse SSPanel-Metron / legacy semicolon server string:
	// e.g. "hk.example.com;port=443#12443;ws;tls;path=/ws;host=hk.example.com"
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
			if parseAnyInt(cc["security"]) > 0 || cc["security"] == "tls" || cc["tls"] == "1" || cc["tls"] == true {
				spec.TLSMode = 1
			}
		}
	}

	// Optionally pull SSPanel-UIM dynamic audit rules (`/mod_mu/func/detect_rules`)
	if rules := c.fetchDetectRules(ctx); len(rules) > 0 {
		spec.Routes = append(spec.Routes, acl.DynamicRoute{
			Matches: rules,
			Action:  "block",
		})
	}

	sum := sha256.Sum256(body)
	spec.ConfigChecksum = hex.EncodeToString(sum[:16])
	return spec, nil
}

func (c *SSPanelClient) fetchDetectRules(ctx context.Context) []string {
	cacheKey := c.baseURL + "|" + c.cfg.WebAPIKey
	now := time.Now().Unix()

	detectCacheMu.RLock()
	if ce, ok := detectCache[cacheKey]; ok && ce.expires > now {
		rules := ce.rules
		detectCacheMu.RUnlock()
		return rules
	}
	detectCacheMu.RUnlock()

	body, _, _, err := c.doGet(ctx, c.modURL("/mod_mu/func/detect_rules", true), "")
	if err != nil {
		return nil
	}
	var resp struct {
		Ret  int `json:"ret"`
		Data []struct {
			Regex string `json:"regex"`
			Type  int    `json:"type"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &resp) != nil || resp.Ret != 1 {
		return nil
	}
	var out []string
	for _, r := range resp.Data {
		if r.Regex != "" {
			out = append(out, "regexp:"+r.Regex)
		}
	}

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
	parts := strings.Split(srv, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i == 0 {
			// Sometimes host:port#listenPort
			if idx := strings.IndexByte(part, '#'); idx > 0 {
				if p, err := strconv.Atoi(part[idx+1:]); err == nil && p > 0 {
					spec.ServerPort = p
				}
			} else if _, portStr, err := strings.Cut(part, ":"); err {
				if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && spec.ServerPort == 0 {
					spec.ServerPort = p
				}
			}
			continue
		}
		lower := strings.ToLower(part)
		switch lower {
		case "ws":
			spec.Network = "ws"
		case "tls":
			spec.TLSMode = 1
		default:
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				if p, err := strconv.Atoi(part); err == nil && p > 0 && spec.ServerPort == 0 {
					spec.ServerPort = p
				}
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "port":
				if _, right, hasHash := strings.Cut(v, "#"); hasHash {
					if p, err := strconv.Atoi(right); err == nil && p > 0 {
						spec.ServerPort = p
					}
				} else if p, err := strconv.Atoi(v); err == nil && p > 0 {
					spec.ServerPort = p
				}
			case "server_port", "inside_port":
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
			case "server_key":
				spec.ServerKey = v
			}
		}
	}
}

type sspanelUsersResp struct {
	Ret  int `json:"ret"`
	Data []struct {
		ID             int     `json:"id"`
		UUID           string  `json:"uuid"`
		Passwd         string  `json:"passwd"`
		NodeSpeedlimit float64 `json:"node_speedlimit"`
		NodeConnector  int     `json:"node_connector"`
	} `json:"data"`
}

func (c *SSPanelClient) FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error) {
	c.mu.Lock()
	etag := c.usersETag
	nodeSpeed := c.nodeSpeed
	nodeConn := c.nodeConn
	c.mu.Unlock()

	u := c.modURL("/mod_mu/users", true)
	body, newETag, status, err := c.doGet(ctx, u, etag)
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch SSPanel users (HTTP %d): %w", status, err)
	}

	var resp sspanelUsersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode SSPanel users: %w", err)
	}
	if resp.Ret != 1 {
		return nil, fmt.Errorf("SSPanel users returned ret=%d", resp.Ret)
	}
	if newETag != "" {
		c.mu.Lock()
		c.usersETag = newETag
		c.mu.Unlock()
	}

	needUUID := c.cfg.NormalizedServerType() == "vless" || c.cfg.NormalizedServerType() == "vmess"
	out := make([]stats.SyncUserSpec, 0, len(resp.Data))
	for _, item := range resp.Data {
		cred := item.Passwd
		if needUUID && item.UUID != "" {
			cred = item.UUID
		} else if cred == "" {
			cred = item.UUID
		}
		if item.ID <= 0 || cred == "" {
			continue
		}
		mbps := item.NodeSpeedlimit
		if nodeSpeed > 0 && (mbps <= 0 || nodeSpeed < mbps) {
			mbps = nodeSpeed
		}
		dev := item.NodeConnector
		if nodeConn > 0 && (dev <= 0 || nodeConn < dev) {
			dev = nodeConn
		}
		out = append(out, stats.SyncUserSpec{
			ID:          item.ID,
			UUIDOrPass:  cred,
			SpeedLimit:  int64(mbps * 125000.0),
			DeviceLimit: dev,
		})
	}
	return out, nil
}

func (c *SSPanelClient) FetchAliveList(_ context.Context) (map[int][]string, error) {
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
		return nil, "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, ifNoneMatch, http.StatusNotModified, ErrNotModified
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, "", resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return body, resp.Header.Get("ETag"), resp.StatusCode, nil
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
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return nil
}
