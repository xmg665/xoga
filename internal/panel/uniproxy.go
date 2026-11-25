package panel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"time"

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

	mu            sync.Mutex
	configETag    string
	usersETag     string
	lastUsersHash [32]byte
	hasUsersHash  bool
	lastBodyLen   int
	legacyV2      bool // fallback node_type="v2ray" when older V2Board rejects "vmess"
	legacyHy      bool // fallback node_type="hysteria" when Xboard/V2Board uses "hysteria" (v2) instead of "hysteria2"
}

func NewUniProxyClient(cfg *config.Config, httpCli *http.Client) *UniProxyClient {
	nt := cfg.NormalizedServerType()
	if strings.EqualFold(cfg.ServerType, "v2ray") {
		nt = "v2ray"
	} else if strings.EqualFold(cfg.ServerType, "hysteria") {
		nt = "hysteria"
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
	if c.legacyHy && nt == "hysteria2" {
		nt = "hysteria"
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
	TLSSettingsAlt  json.RawMessage `json:"tlsSettings"`
	Host            string          `json:"host"`
	ServerName      string          `json:"server_name"`
	Flow            string          `json:"flow"`
	Version         int             `json:"version"`
	UpMbps          int             `json:"up_mbps"`
	DownMbps        int             `json:"down_mbps"`
	Obfs            string          `json:"obfs"`
	ObfsPassword    string          `json:"obfs-password"`
	ObfsPasswordAlt string          `json:"obfs_password"`
	PaddingScheme   json.RawMessage `json:"padding_scheme"`
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
	if err != nil && (status == 400 || status == 404 || status == 422 || status == 500) {
		if c.nodeType == "vmess" {
			c.mu.Lock()
			c.legacyV2 = true
			c.mu.Unlock()
			body, newETag, status, err = c.doGet(ctx, c.endpoint("config"), "")
		} else if c.nodeType == "hysteria2" {
			// Xboard registers Hysteria v2 under `node_type=hysteria` with `"version": 2`
			c.mu.Lock()
			c.legacyHy = true
			c.mu.Unlock()
			body, newETag, status, err = c.doGet(ctx, c.endpoint("config"), "")
		}
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
	switch proto {
	case "", "v2ray":
		proto = c.cfg.NormalizedServerType()
	case "hysteria", "hy2":
		proto = "hysteria2"
	}

	spec := &NodeSpec{
		Protocol:          proto,
		ListenIP:          raw.ListenIP,
		ServerPort:        raw.ServerPort,
		Network:           strings.ToLower(raw.Network),
		Cipher:            strings.ToLower(raw.Cipher),
		ServerKey:         raw.ServerKey,
		TLSMode:           raw.TLS,
		ServerName:        raw.ServerName,
		Flow:              raw.Flow,
		PullInterval:      parseAnyInt(raw.BaseConfig.PullInterval),
		PushInterval:      parseAnyInt(raw.BaseConfig.PushInterval),
		Hy2UpMbps:         raw.UpMbps,
		Hy2DownMbps:       raw.DownMbps,
		Hy2Obfs:           strings.ToLower(strings.TrimSpace(raw.Obfs)),
		Hy2ObfsPassword:   strings.TrimSpace(raw.ObfsPassword),
		Hy2IgnoreClientBW: c.cfg.Hy2IgnoreClientBW,
	}
	if spec.Hy2ObfsPassword == "" && raw.ObfsPasswordAlt != "" {
		spec.Hy2ObfsPassword = strings.TrimSpace(raw.ObfsPasswordAlt)
	}
	// V2bX / V2Board compatibility: when `obfs` contains a password string directly and `obfs-password` is empty
	if spec.Hy2Obfs != "" && spec.Hy2Obfs != "salamander" && spec.Hy2ObfsPassword == "" {
		spec.Hy2ObfsPassword = raw.Obfs
		spec.Hy2Obfs = "salamander"
	}
	if proto == "hysteria2" || proto == "anytls" {
		if spec.TLSMode == 0 {
			spec.TLSMode = 1
		}
	}
	if spec.Flow == "" && c.cfg.VLESSFlow != "" {
		spec.Flow = c.cfg.VLESSFlow
	}
	if c.cfg.IsRealityConfigured() && spec.TLSMode != 2 {
		spec.TLSMode = 2
	}
	if spec.ListenIP == "" {
		spec.ListenIP = "0.0.0.0"
	}
	if spec.Network == "" {
		if proto == "hysteria2" {
			spec.Network = "quic"
		} else {
			spec.Network = "tcp"
		}
	}
	if spec.ServerName == "" && raw.Host != "" {
		spec.ServerName = raw.Host
	}

	// Parse AnyTLS padding_scheme (either string or []string in Xboard)
	if len(raw.PaddingScheme) > 0 {
		var s string
		var arr []string
		if json.Unmarshal(raw.PaddingScheme, &s) == nil && s != "" {
			spec.AnyTLSPaddingScheme = s
		} else if json.Unmarshal(raw.PaddingScheme, &arr) == nil && len(arr) > 0 {
			spec.AnyTLSPaddingScheme = strings.Join(arr, "\n")
		}
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

	// Extract TLS & REALITY settings from tls_settings / tlsSettings
	tsBytes := raw.TLSSettings
	if len(tsBytes) == 0 {
		tsBytes = raw.TLSSettingsAlt
	}
	if len(tsBytes) > 2 {
		var ts struct {
			ServerName  string   `json:"server_name"`
			ServerNames []string `json:"server_names"`
			ServerPort  any      `json:"server_port"`
			Dest        string   `json:"dest"`
			ShortID     string   `json:"short_id"`
			ShortIDs    []string `json:"short_ids"`
			PrivateKey  string   `json:"private_key"`
		}
		if json.Unmarshal(tsBytes, &ts) == nil {
			if ts.ServerName != "" {
				spec.ServerName = ts.ServerName
			}
			if ts.PrivateKey != "" {
				spec.RealityPrivateKey = strings.TrimSpace(ts.PrivateKey)
			}
			if ts.Dest != "" {
				spec.RealityDest = strings.TrimSpace(ts.Dest)
			} else if ts.ServerName != "" {
				dp := parseAnyInt(ts.ServerPort)
				if dp <= 0 {
					dp = 443
				}
				spec.RealityDest = net.JoinHostPort(ts.ServerName, strconv.Itoa(dp))
			}
			if len(ts.ServerNames) > 0 {
				spec.RealityServerNames = append(spec.RealityServerNames, ts.ServerNames...)
			} else if ts.ServerName != "" {
				for _, sn := range strings.Split(ts.ServerName, ",") {
					if s := strings.TrimSpace(sn); s != "" {
						spec.RealityServerNames = append(spec.RealityServerNames, s)
					}
				}
			}
			if len(ts.ShortIDs) > 0 {
				spec.RealityShortIDs = append(spec.RealityShortIDs, ts.ShortIDs...)
			} else if ts.ShortID != "" {
				for _, sid := range strings.Split(ts.ShortID, ",") {
					spec.RealityShortIDs = append(spec.RealityShortIDs, strings.TrimSpace(sid))
				}
			}
		}
	}

	applyConfigProtocolOverrides(c.cfg, spec)
	if spec.TLSMode == 2 && spec.RealityPrivateKey == "" {
		// V2bX / V2Board deterministic X25519 private key derivation fallback
		sum := sha256.Sum256([]byte("vless" + c.cfg.WebAPIKey))
		sum[0] &= 248
		sum[31] &= 127
		sum[31] |= 64
		spec.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(sum[:])
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
		ID             int    `json:"id"`
		UUID           string `json:"uuid"`
		SpeedLimit     *int   `json:"speed_limit"`
		DeviceLimit    *int   `json:"device_limit"`
		Banned         *int   `json:"banned"`
		ExpiredAt      *int64 `json:"expired_at"`
		U              *int64 `json:"u"`
		D              *int64 `json:"d"`
		TransferEnable *int64 `json:"transfer_enable"`
	} `json:"users"`
}

func applyConfigProtocolOverrides(cfg *config.Config, spec *NodeSpec) {
	if cfg.VLESSFlow != "" && spec.Flow == "" {
		spec.Flow = cfg.VLESSFlow
	}
	if cfg.RealityDest != "" {
		spec.RealityDest = cfg.RealityDest
	}
	if cfg.RealityPrivateKey != "" {
		spec.RealityPrivateKey = cfg.RealityPrivateKey
	}
	if len(cfg.RealityShortIDs) > 0 {
		spec.RealityShortIDs = append([]string(nil), cfg.RealityShortIDs...)
	}
	if len(cfg.RealityServerNames) > 0 {
		spec.RealityServerNames = append([]string(nil), cfg.RealityServerNames...)
	}
	if cfg.Hy2Obfs != "" {
		spec.Hy2Obfs = cfg.Hy2Obfs
	}
	if cfg.Hy2ObfsPassword != "" {
		spec.Hy2ObfsPassword = cfg.Hy2ObfsPassword
	}
	if cfg.Hy2UpMbps > 0 {
		spec.Hy2UpMbps = cfg.Hy2UpMbps
	}
	if cfg.Hy2DownMbps > 0 {
		spec.Hy2DownMbps = cfg.Hy2DownMbps
	}
	if cfg.Hy2IgnoreClientBW {
		spec.Hy2IgnoreClientBW = true
	}
	if cfg.AnyTLSPadding != "" {
		spec.AnyTLSPaddingScheme = cfg.AnyTLSPadding
	}
}

func (c *UniProxyClient) FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error) {
	c.mu.Lock()
	etag := c.usersETag
	prevHash := c.lastUsersHash
	hasPrevHash := c.hasUsersHash
	c.mu.Unlock()

	body, newETag, status, err := c.doGet(ctx, c.endpoint("user"), etag)
	if errors.Is(err, ErrNotModified) {
		return nil, ErrNotModified
	}
	if err != nil {
		return nil, fmt.Errorf("fetch UniProxy users (HTTP %d): %w", status, err)
	}

	bodyHash := sha256.Sum256(body)
	if hasPrevHash && bodyHash == prevHash {
		return nil, ErrNotModified
	}

	var resp uniUsersResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode UniProxy users: %w", err)
	}

	c.mu.Lock()
	c.lastUsersHash = bodyHash
	c.hasUsersHash = true
	if newETag != "" {
		c.usersETag = newETag
	}
	c.mu.Unlock()

	nowUnix := time.Now().Unix()
	out := make([]stats.SyncUserSpec, 0, len(resp.Users))
	for _, u := range resp.Users {
		if u.ID <= 0 || u.UUID == "" {
			continue
		}
		if u.Banned != nil && *u.Banned != 0 {
			continue
		}
		if u.ExpiredAt != nil && *u.ExpiredAt > 0 && *u.ExpiredAt <= nowUnix {
			continue
		}
		var remain int64 = -1
		if u.TransferEnable != nil && *u.TransferEnable > 0 {
			var used int64
			if u.U != nil {
				used += *u.U
			}
			if u.D != nil {
				used += *u.D
			}
			remain = *u.TransferEnable - used
			if remain <= 0 {
				continue
			}
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
			RemainBytes: remain,
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
	body, err := readResponseBody(resp, &c.lastBodyLen)
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
