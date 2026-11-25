package panel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/xmg665/xoga/internal/acl"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/stats"
)

// ErrNotModified indicates the panel returned HTTP 304 Not Modified via ETag short-circuiting.
var ErrNotModified = errors.New("panel resource not modified (304)")

// NodeSpec represents normalized inbound server parameters pulled from the panel.
type NodeSpec struct {
	Protocol       string // vless, vmess, trojan, shadowsocks
	ListenIP       string
	ServerPort     int
	Network        string // tcp, ws
	WSPath         string
	WSHost         string
	Cipher         string // aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm
	ServerKey      string // Shadowsocks-2022 base64 PSK
	TLSMode        int    // 0: none, 1: tls, 2: reality (fallback to tls)
	ServerName     string
	Flow           string
	PullInterval   int
	PushInterval   int
	Routes         []acl.DynamicRoute
	ConfigChecksum string
}

// SystemStatus holds lightweight host resource metrics reported to the panel.
type SystemStatus struct {
	CPU       float64
	MemTotal  uint64
	MemUsed   uint64
	SwapTotal uint64
	SwapUsed  uint64
	DiskTotal uint64
	DiskUsed  uint64
	LoadAvg   string
	UptimeSec uint64
}

// Client abstracts communication with V2Board/Xboard (UniProxy) and SSPanel (mod_mu).
type Client interface {
	Name() string
	FetchNodeConfig(ctx context.Context) (*NodeSpec, error)
	FetchUsers(ctx context.Context) ([]stats.SyncUserSpec, error)
	FetchAliveList(ctx context.Context) (map[int][]string, error)
	PushTraffic(ctx context.Context, batch []stats.TrafficDelta) error
	PushAlive(ctx context.Context, alive map[int][]string) error
	PushStatus(ctx context.Context, st SystemStatus) error
}

func NewClient(cfg *config.Config) (Client, error) {
	return NewClientWithHTTP(cfg, NewKeepAliveHTTPClient(4))
}

func NewClientWithHTTP(cfg *config.Config, httpCli *http.Client) (Client, error) {
	if httpCli == nil {
		httpCli = NewKeepAliveHTTPClient(4)
	}
	switch cfg.NormalizedPanelType() {
	case "uniproxy":
		return NewUniProxyClient(cfg, httpCli), nil
	case "sspanel":
		return NewSSPanelClient(cfg, httpCli), nil
	default:
		return nil, fmt.Errorf("unsupported panel type: %s", cfg.Type)
	}
}

// NewKeepAliveHTTPClient constructs a low-memory HTTP/1.1 & HTTP/2 client reusing persistent
// TCP/TLS connections across polling ticks so multi-node instances avoid repeated TLS handshakes.
func NewKeepAliveHTTPClient(maxPerHost int) *http.Client {
	if maxPerHost < 2 {
		maxPerHost = 2
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxPerHost * 2,
		MaxIdleConnsPerHost:   maxPerHost,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ReadBufferSize:        8 * 1024,
		WriteBufferSize:       8 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second,
	}
}
