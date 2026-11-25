package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultConfigDir  = "/etc/xoga"
	DefaultConfigPath = "/etc/xoga/xoga.conf"
	DefaultBinDir     = "/usr/local/xoga"
)

// Config represents the complete node configuration, 100% compatible with soga.conf keys
// plus CPU & memory runtime optimization parameters.
type Config struct {
	// Base panel settings
	Type       string // v2board, xboard, newv2board, sspanel
	ServerType string // v2ray, vmess, vless, trojan, ss, shadowsocks
	NodeID     int
	SogaKey    string // kept for compatibility with soga.conf scripts (unused/free)
	API        string // webapi

	// WebAPI connection
	WebAPIURL string
	WebAPIKey string // supports both webapi_key and webapi_mukey

	// Manual TLS certificates
	CertFile string
	KeyFile  string

	// Automatic ACME certificates
	CertMode      string // http, tls, self, none
	CertDomain    string
	CertKeyLength string
	DNSProvider   string
	ForceCloseSSL bool

	// Transit / Relay
	ProxyProtocol    bool
	UDPProxyProtocol bool
	ListenIP         string
	ListenPort       int // optional local port override (0 = follow panel server_port)

	// Redis global IP limit (RESP wire protocol, zero heavy SDK)
	RedisIPLimitEnable   bool
	RedisIPLimitAddr     string
	RedisIPLimitPassword string
	RedisIPLimitDB       int
	RedisIPLimitTLS      bool
	RedisIPLimitExpiry   int

	// Dynamic speed limiter (soga dy_limit_* compatible)
	DyLimitEnable       bool
	DyLimitDuration     int
	DyLimitTriggerTime  int     // seconds sustaining trigger speed
	DyLimitTriggerSpeed float64 // Mbps threshold
	DyLimitSpeed        float64 // Mbps throttled speed
	DyLimitTime         int     // seconds to throttle
	DyLimitWhiteUserIDs map[int]struct{}

	// Static limits & intervals
	UserConnLimit       int     // max concurrent IP/devices per user (0 = follow panel device_limit)
	UserSpeedLimit      float64 // Mbps static per-user cap (0 = follow panel speed_limit)
	UserTCPLimit        int     // max concurrent TCP streams per user (0 = unlimited)
	NodeSpeedLimit      float64 // Mbps total node cap (0 = unlimited)
	CheckInterval       int      // seconds between panel config/user pulls
	SubmitInterval      int      // seconds between traffic/alive pushes
	ForbiddenBitTorrent bool
	ForbiddenPorts      string   // e.g. "25,26,6881-6999" (soga forbidden_ports)
	BanPrivateIP        bool     // block RFC1918/loopback targets when true
	VLESS               bool     // soga `vless=true` when `server_type=v2ray`
	VLESSFlow           string   // soga `vless_flow=`
	V2rayReduceMemory   bool     // soga `v2ray_reduce_memory=true`
	DefaultDNS          []string
	DNSStrategy         string // ipv4_first, ipv6_first, ipv4_only, ipv6_only
	DNSCacheTime        int    // minutes (soga `dns_cache_time=10`)
	DNSConfigURL        string // optional remote URL to fetch dns.yml
	DomainSniff         bool   // rewrite target IP with sniffed SNI/Host when matching DNS/route unlock rules
	ForceDomainSniff    bool   // always rewrite target IP with sniffed SNI/Host
	LogLevel            string

	// Rule file paths
	BlockListPath string
	WhiteListPath string
	RoutesPath    string
	DNSConfigPath string

	// CPU & Memory optimization settings (xoga enhancements)
	EnableZeroCopy bool // Linux splice(2) kernel zero-copy when unthrottled
	MemLimitMB     int  // Soft GOMEMLIMIT in MiB (0 = auto 128 MiB)
	GCPercent      int  // Go GOGC target percentage (default 50 for low RSS)
	ConnIdleSec    int  // Idle TCP stream timeout in seconds (default 300)
	UDPIdleSec     int  // Idle UDP session timeout in seconds (default 60)

	// Raw key-value preservation for `xoga config` editing
	RawPath string
}

func Default() *Config {
	return &Config{
		Type:                "v2board",
		ServerType:          "vless",
		API:                 "webapi",
		CertKeyLength:       "ec-256",
		RedisIPLimitExpiry:  60,
		DyLimitTriggerTime:  60,
		DyLimitTriggerSpeed: 100,
		DyLimitSpeed:        30,
		DyLimitTime:         600,
		DyLimitWhiteUserIDs: make(map[int]struct{}),
		CheckInterval:       60,
		SubmitInterval:      60,
		ForbiddenBitTorrent: true,
		DNSStrategy:         "ipv4_first",
		DomainSniff:         true,
		LogLevel:            "info",
		EnableZeroCopy:      true,
		MemLimitMB:          128,
		GCPercent:           50,
		ConnIdleSec:         300,
		UDPIdleSec:          60,
	}
}

// Load parses a soga.conf / xoga.conf INI-style key=value file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := Default()
	cfg.RawPath = path
	baseDir := filepath.Dir(path)
	cfg.BlockListPath = filepath.Join(baseDir, "blockList")
	cfg.WhiteListPath = filepath.Join(baseDir, "whiteList")
	cfg.RoutesPath = filepath.Join(baseDir, "routes.toml")
	cfg.DNSConfigPath = filepath.Join(baseDir, "dns.yml")

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip inline comments unless inside quotes
		if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") && len(val) >= 2 {
			val = val[1 : len(val)-1]
		} else if idx := strings.Index(val, " #"); idx >= 0 {
			val = strings.TrimSpace(val[:idx])
		}
		cfg.ApplyKV(key, val)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) ApplyKV(key, val string) {
	switch strings.ToLower(key) {
	case "type":
		c.Type = strings.ToLower(val)
	case "server_type":
		c.ServerType = strings.ToLower(val)
	case "node_id":
		c.NodeID, _ = strconv.Atoi(val)
	case "soga_key":
		c.SogaKey = val
	case "api":
		if val != "" {
			c.API = strings.ToLower(val)
		}
	case "webapi_url":
		c.WebAPIURL = strings.TrimRight(val, "/")
	case "webapi_key", "webapi_mukey":
		if val != "" {
			c.WebAPIKey = val
		}
	case "cert_file":
		c.CertFile = val
	case "key_file":
		c.KeyFile = val
	case "cert_mode":
		c.CertMode = strings.ToLower(val)
	case "cert_domain":
		c.CertDomain = val
	case "cert_key_length":
		c.CertKeyLength = val
	case "dns_provider":
		c.DNSProvider = val
	case "force_close_ssl":
		c.ForceCloseSSL = parseBool(val, false)
	case "proxy_protocol":
		c.ProxyProtocol = parseBool(val, false)
	case "udp_proxy_protocol":
		c.UDPProxyProtocol = parseBool(val, false)
	case "listen_ip":
		c.ListenIP = val
	case "listen_port":
		c.ListenPort, _ = strconv.Atoi(val)
	case "redis_ip_limit_enable", "redis_enable":
		c.RedisIPLimitEnable = parseBool(val, false)
	case "redis_ip_limit_addr", "redis_addr":
		c.RedisIPLimitAddr = val
	case "redis_ip_limit_password", "redis_password":
		c.RedisIPLimitPassword = val
	case "redis_ip_limit_db", "redis_db":
		c.RedisIPLimitDB, _ = strconv.Atoi(val)
	case "redis_ip_limit_tls", "redis_tls":
		c.RedisIPLimitTLS = parseBool(val, false)
	case "redis_ip_limit_expiry", "conn_limit_expiry":
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			c.RedisIPLimitExpiry = n
		}
	case "dy_limit_enable":
		c.DyLimitEnable = parseBool(val, false)
	case "dy_limit_duration":
		c.DyLimitDuration, _ = strconv.Atoi(val)
	case "dy_limit_trigger_time":
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			c.DyLimitTriggerTime = n
		}
	case "dy_limit_trigger_speed":
		if f, err := strconv.ParseFloat(val, 64); err == nil && f > 0 {
			c.DyLimitTriggerSpeed = f
		}
	case "dy_limit_speed":
		if f, err := strconv.ParseFloat(val, 64); err == nil && f >= 0 {
			c.DyLimitSpeed = f
		}
	case "dy_limit_time":
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			c.DyLimitTime = n
		}
	case "dy_limit_white_user_id":
		c.DyLimitWhiteUserIDs = make(map[int]struct{})
		for _, part := range strings.Split(val, ",") {
			if id, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && id > 0 {
				c.DyLimitWhiteUserIDs[id] = struct{}{}
			}
		}
	case "user_conn_limit":
		c.UserConnLimit, _ = strconv.Atoi(val)
	case "user_speed_limit":
		c.UserSpeedLimit, _ = strconv.ParseFloat(val, 64)
	case "user_tcp_limit":
		c.UserTCPLimit, _ = strconv.Atoi(val)
	case "node_speed_limit":
		c.NodeSpeedLimit, _ = strconv.ParseFloat(val, 64)
	case "check_interval":
		if n, err := strconv.Atoi(val); err == nil && n >= 5 {
			c.CheckInterval = n
		}
	case "submit_interval":
		if n, err := strconv.Atoi(val); err == nil && n >= 5 {
			c.SubmitInterval = n
		}
	case "forbidden_bit_torrent":
		c.ForbiddenBitTorrent = parseBool(val, true)
	case "forbidden_ports":
		c.ForbiddenPorts = strings.TrimSpace(val)
	case "ban_private_ip":
		c.BanPrivateIP = parseBool(val, false)
	case "vless":
		c.VLESS = parseBool(val, false)
	case "vless_flow":
		c.VLESSFlow = strings.TrimSpace(val)
	case "v2ray_reduce_memory":
		c.V2rayReduceMemory = parseBool(val, false)
		if c.V2rayReduceMemory && c.GCPercent == 50 {
			c.GCPercent = 35
		}
	case "dns_cache_time":
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			c.DNSCacheTime = n
		}
	case "default_dns":
		c.DefaultDNS = nil
		for _, d := range strings.Split(val, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				c.DefaultDNS = append(c.DefaultDNS, d)
			}
		}
	case "dns_strategy":
		if val != "" {
			c.DNSStrategy = strings.ToLower(val)
		}
	case "dns_config_url":
		c.DNSConfigURL = strings.TrimSpace(val)
	case "domain_sniff":
		c.DomainSniff = parseBool(val, true)
	case "force_domain_sniff":
		c.ForceDomainSniff = parseBool(val, false)
	case "dns_file", "dns_config_file":
		c.DNSConfigPath = val
	case "log_level":
		if val != "" {
			c.LogLevel = strings.ToLower(val)
		}
	case "block_list_file":
		c.BlockListPath = val
	case "white_list_file":
		c.WhiteListPath = val
	case "routes_file":
		c.RoutesPath = val
	case "enable_zero_copy":
		c.EnableZeroCopy = parseBool(val, true)
	case "mem_limit_mb":
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			c.MemLimitMB = n
		}
	case "gc_percent":
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			c.GCPercent = n
		}
	case "conn_idle_sec":
		if n, err := strconv.Atoi(val); err == nil && n >= 15 {
			c.ConnIdleSec = n
		}
	case "udp_idle_sec":
		if n, err := strconv.Atoi(val); err == nil && n >= 10 {
			c.UDPIdleSec = n
		}
	}
}

func (c *Config) Validate() error {
	if c.NodeID <= 0 {
		return errors.New("node_id must be greater than 0")
	}
	if c.WebAPIURL == "" {
		return errors.New("webapi_url is required")
	}
	if c.WebAPIKey == "" {
		return errors.New("webapi_key is required")
	}
	switch c.NormalizedPanelType() {
	case "uniproxy", "sspanel":
	default:
		return fmt.Errorf("unsupported panel type %q (supported: v2board, newv2board, xboard, sspanel)", c.Type)
	}
	switch c.NormalizedServerType() {
	case "vless", "vmess", "trojan", "shadowsocks":
	default:
		return fmt.Errorf("unsupported server_type %q (supported: v2ray, vmess, vless, trojan, ss, shadowsocks)", c.ServerType)
	}
	return nil
}

func (c *Config) NormalizedPanelType() string {
	switch strings.ToLower(c.Type) {
	case "v2board", "newv2board", "xboard", "v2board-new", "uniproxy":
		return "uniproxy"
	case "sspanel", "sspanel-uim", "sspanel_uim", "metron":
		return "sspanel"
	default:
		return ""
	}
}

func (c *Config) NormalizedServerType() string {
	switch strings.ToLower(c.ServerType) {
	case "v2ray", "vmess":
		if c.VLESS {
			return "vless"
		}
		return "vmess"
	case "vless":
		return "vless"
	case "trojan":
		return "trojan"
	case "ss", "shadowsocks":
		return "shadowsocks"
	default:
		return ""
	}
}

// UpdateFile updates or appends k=v pairs in-place while preserving comments and layout,
// matching `soga config k1=v1 k2=v2` behavior.
func UpdateFile(path string, pairs []string) ([]string, error) {
	var existingLines []string
	if data, err := os.ReadFile(path); err == nil {
		raw := strings.ReplaceAll(string(data), "\r\n", "\n")
		existingLines = strings.Split(raw, "\n")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		existingLines = strings.Split(DefaultTemplate(), "\n")
	}

	var applied []string
	for _, kv := range pairs {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val := kv[eq+1:]
		if key == "" {
			continue
		}
		replaced := false
		for i, line := range existingLines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
				continue
			}
			leq := strings.IndexByte(trimmed, '=')
			if leq <= 0 {
				continue
			}
			lkey := strings.TrimSpace(trimmed[:leq])
			if strings.EqualFold(lkey, key) {
				existingLines[i] = key + "=" + val
				replaced = true
				break
			}
		}
		if !replaced {
			existingLines = append(existingLines, key+"="+val)
		}
		applied = append(applied, key+"="+val)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	out := strings.Join(existingLines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0640); err != nil {
		return nil, err
	}
	return applied, nil
}

func DefaultTemplate() string {
	return `# ==================== 基础对接配置 (兼容 soga.conf) ====================
type=v2board
server_type=vless
node_id=1
api=webapi

# webapi 对接信息
webapi_url=
webapi_key=

# 手动证书配置
cert_file=
key_file=

# 自动证书配置 (http / self / 空)
cert_mode=
cert_domain=
cert_key_length=ec-256
force_close_ssl=false

# proxy protocol 中转配置
proxy_protocol=false
udp_proxy_protocol=false

# 全局限制用户 IP 数配置 (原生轻量 RESP 协议，无需重量级 SDK)
redis_ip_limit_enable=false
redis_ip_limit_addr=
redis_ip_limit_password=
redis_ip_limit_db=0
redis_ip_limit_tls=false
redis_ip_limit_expiry=60

# 动态限速配置
dy_limit_enable=false
dy_limit_trigger_time=60
dy_limit_trigger_speed=100
dy_limit_speed=30
dy_limit_time=600
dy_limit_white_user_id=

# 流控与同步间隔
user_conn_limit=0
user_speed_limit=0
user_tcp_limit=0
node_speed_limit=0

check_interval=60
submit_interval=60
forbidden_bit_torrent=true
default_dns=
dns_strategy=ipv4_first
dns_config_url=
domain_sniff=true
log_level=info

# ==================== CPU & 内存深度优化配置 ====================
enable_zero_copy=true
mem_limit_mb=128
gc_percent=50
conn_idle_sec=300
udp_idle_sec=60
`
}

func parseBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
