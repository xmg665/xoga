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

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

// UniProxyClient implements V2Board / NewV2Board / Xboard `/api/v1/server/UniProxy/*` with ETag caching.
type UniProxyClient struct {
	cfg      *config.Config
	http     *http.Client
	baseURL  string
	nodeType string

	mu         sync.Mutex
	configETag string
	usersETag  string
	legacyV2   bool // fallback node_type="v2ray" when older V2Board rejects "vmess"
}

func NewUniProxyClient(cfg *config.Config, httpCli *http.Client) *UniProxyClient {
	nt := cfg.NormalizedServerType()
	if strings.EqualFold(cfg.ServerType, "v2ray") {
		nt = "v2ray"
	}
	return &UniProxyClient{
		cfg:      cfg,
		http:     httpCli,
		baseURL:  strings.TrimRight(cfg.WebAPIURL, "/"),
		nodeType: nt,
	}
}

func (c *UniProxyClient) Name() string {
	return "UniProxy(" + c.cfg.Type + ")"
}

func (c *UniProxyClient) endpoint(action string) string {
	c.mu.Lock()
	nt := c.nodeType
	if c.legacyV2 && nt == "vmess" {
		nt = "v2ray"
	}
	c.mu.Unlock()

	q := url.Values{}
	q.Set("node_id", strconv.Itoa(c.cfg.NodeID))
	q.Set("node_type", nt)
	q.Set("token", c.cfg.WebAPIKey)
	return c.baseURL + "/api/v1/server/UniProxy/" + action + "?" + q.Encode()
}

type uniConfigResp struct {
	Protocol        string          `json:"protocol"`
	ListenIP        string          `json:"listen_ip"`
	ServerPort      int             `json:"server_port"`
	Network         string          `json:"network"`
	NetworkSettings json.RawMessage `json:"networkSettings"`
	NetSettingsAlt  json.RawMessage `json:"network_settings"`
	Cipher          string          `json:"cipher"`
	ServerKey       string          `json:"server_key"`
	TLS             int             `json:"tls"`
	TLSSettings     json.RawMessage `json:"tls_settings"`
	Host            string          `json:"host"`
	ServerName      string          `json:"server_name"`
	Flow            string          `json:"flow"`
	Routes          []struct {
		ID          int             `json:"id"`
		Match       json.RawMessage `json:"match"`
		Action      string          `json:"action"`
		ActionValue string          `json:"action_value"`
	} `json:"routes"`
	BaseConfig struct {
		PushInterval any `json:"push_interval"`
		PullInterval any `json:"pull_interval"`
	} `json:"base_config"`
}

func (c *UniProxyClient) FetchNodeConfig(ctx context.Context) (*NodeSpec, error) {
	c.mu.Lock()
	etag := c.configETag
	c.mu.Unlock()

	body, newETag, status, err := c.doGet(ctx, c.endpoint("config"), etag)
	if err != nil && (status == 400 || status == 404 || status == 500) && c.nodeType == "vmess" {
		// Retry once with legacy V2Board node_type=v2ray
		c.mu.Lock()
		c.legacyV2 = true
		c.mu.Unlock()
		body, newETag, status, err = c.doGet(ctx, c.endpoint("config"), "")
	}
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch UniProxy config (HTTP %d): %w", status, err)
	}

	var raw uniConfigResp
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode UniProxy config: %w", err)
	}

	if newETag != "" {
		c.mu.Lock()
		c.configETag = newETag
		c.mu.Unlock()
	}

	proto := strings.ToLower(raw.Protocol)
	if proto == "" || proto == "v2ray" {
		proto = c.cfg.NormalizedServerType()
	}

	spec := &NodeSpec{
		Protocol:     proto,
		ListenIP:     raw.ListenIP,
		ServerPort:   raw.ServerPort,
		Network:      strings.ToLower(raw.Network),
		Cipher:       strings.ToLower(raw.Cipher),
		ServerKey:    raw.ServerKey,
		TLSMode:      raw.TLS,
		ServerName:   raw.ServerName,
		Flow:         raw.Flow,
		PullInterval: parseAnyInt(raw.BaseConfig.PullInterval),
		PushInterval: parseAnyInt(raw.BaseConfig.PushInterval),
	}
	if spec.ListenIP == "" {
		spec.ListenIP = "0.0.0.0"
	}
	if spec.Network == "" {
		spec.Network = "tcp"
	}
	if spec.ServerName == "" && raw.Host != "" {
		spec.ServerName = raw.Host
	}

	// Extract WS path & host from networkSettings / network_settings
	nsBytes := raw.NetworkSettings
	if len(nsBytes) == 0 {
		nsBytes = raw.NetSettingsAlt
	}
	if len(nsBytes) > 2 {
		var ns struct {
			Path    string            `json:"path"`
			Headers map[string]string `json:"headers"`
			Host    string            `json:"host"`
		}
		if json.Unmarshal(nsBytes, &ns) == nil {
			spec.WSPath = ns.Path
			if ns.Host != "" {
				spec.WSHost = ns.Host
			} else if h, ok := ns.Headers["Host"]; ok {
				spec.WSHost = h
			} else if h, ok := ns.Headers["host"]; ok {
				spec.WSHost = h
			}
		}
	}

	// Extract server_name from tls_settings when needed
	if spec.ServerName == "" && len(raw.TLSSettings) > 2 {
		var ts struct {
			ServerName string `json:"server_name"`
		}
		if json.Unmarshal(raw.TLSSettings, &ts) == nil && ts.ServerName != "" {
			spec.ServerName = ts.ServerName
		}
	}

	// Convert dynamic panel routes
	for _, r := range raw.Routes {
		matches := parseRouteMatches(r.Match)
		if len(matches) > 0 {
			spec.Routes = append(spec.Routes, acl.DynamicRoute{
				Matches:     matches,
				Action:      r.Action,
				ActionValue: r.ActionValue,
			})
		}
	}

	sum := sha256.Sum256(body)
	spec.ConfigChecksum = hex.EncodeToString(sum[:16])
	return spec, nil
}

type uniUsersResp struct {
	Users []struct {
		ID          int  `json:"id"`
		UUID        string `json:"uuid"`
		SpeedLimit  *int `json:"speed_limit"`
		DeviceLimit *int `json:"device_limit"`
	} `json:"users"`
}

func (c *UniProxyClient) FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error) {
	c.mu.Lock()
	etag := c.usersETag
	c.mu.Unlock()

	body, newETag, status, err := c.doGet(ctx, c.endpoint("user"), etag)
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch UniProxy users (HTTP %d): %w", status, err)
	}

	var resp uniUsersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode UniProxy users: %w", err)
	}

	if newETag != "" {
		c.mu.Lock()
		c.usersETag = newETag
		c.mu.Unlock()
	}

	out := make([]stats.SyncUserSpec, 0, len(resp.Users))
	for _, u := range resp.Users {
		if u.ID <= 0 || u.UUID == "" {
			continue
		}
		var speedBps int64
		if u.SpeedLimit != nil && *u.SpeedLimit > 0 {
			// V2Board / Xboard speed_limit is configured in Mbps (1 Mbps = 125,000 B/s)
			speedBps = int64(*u.SpeedLimit) * 125000
		}
		var devLim int
		if u.DeviceLimit != nil && *u.DeviceLimit > 0 {
			devLim = *u.DeviceLimit
		}
		out = append(out, stats.SyncUserSpec{
			ID:          u.ID,
			UUIDOrPass:  u.UUID,
			SpeedLimit:  speedBps,
			DeviceLimit: devLim,
		})
	}
	return out, nil
}

func (c *UniProxyClient) FetchAliveList(ctx context.Context) (map[int][]string, error) {
	body, _, status, err := c.doGet(ctx, c.endpoint("alivelist"), "")
	if err != nil {
		if status == 404 {
			// Older V2Board builds do not expose /alivelist; gracefully skip
			return nil, nil
		}
		return nil, err
	}
	var wrapper struct {
		Alive map[string]json.RawMessage `json:"alive"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil || len(wrapper.Alive) == 0 {
		return nil, nil
	}
	res := make(map[int][]string, len(wrapper.Alive))
	for uidStr, raw := range wrapper.Alive {
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}
		var ips []string
		if json.Unmarshal(raw, &ips) == nil && len(ips) > 0 {
			res[uid] = ips
		}
	}
	return res, nil
}

func (c *UniProxyClient) PushTraffic(ctx context.Context, batch []stats.TrafficDelta) error {
	if len(batch) == 0 {
		return nil
	}
	// UniProxy /push expects: {"<user_id>": [upload_bytes, download_bytes]}
	payload := make(map[string][2]int64, len(batch))
	for _, item := range batch {
		payload[strconv.Itoa(item.UserID)] = [2]int64{item.Upload, item.Download}
	}
	return c.doPostJSON(ctx, c.endpoint("push"), payload, false)
}

func (c *UniProxyClient) PushAlive(ctx context.Context, alive map[int][]string) error {
	if len(alive) == 0 {
		return nil
	}
	payload := make(map[string][]string, len(alive))
	for uid, ips := range alive {
		if len(ips) > 0 {
			payload[strconv.Itoa(uid)] = ips
		}
	}
	if len(payload) == 0 {
		return nil
	}
	return c.doPostJSON(ctx, c.endpoint("alive"), payload, true)
}

func (c *UniProxyClient) PushStatus(ctx context.Context, st SystemStatus) error {
	payload := map[string]any{
		"cpu": st.CPU,
		"mem": map[string]uint64{
			"total": st.MemTotal,
			"used":  st.MemUsed,
		},
		"swap": map[string]uint64{
			"total": st.SwapTotal,
			"used":  st.SwapUsed,
		},
		"disk": map[string]uint64{
			"total": st.DiskTotal,
			"used":  st.DiskUsed,
		},
	}
	return c.doPostJSON(ctx, c.endpoint("status"), payload, true)
}

func (c *UniProxyClient) doGet(ctx context.Context, fullURL, ifNoneMatch string) ([]byte, string, int, error) {
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
		return nil, "", resp.StatusCode, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return body, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func (c *UniProxyClient) doPostJSON(ctx context.Context, fullURL string, v any, ignore404 bool) error {
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

	if ignore404 && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %d: %s", resp.StatusCode, truncateMsg(body))
	}
	return nil
}

func parseRouteMatches(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return strings.Split(single, ",")
	}
	return nil
}

func parseAnyInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func truncateMsg(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
