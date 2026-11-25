package transport

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/xtls/reality"
)

// RealityOptions configures a server-side REALITY TLS 1.3 camouflage listener.
type RealityOptions struct {
	Dest        string
	PrivateKey  string
	ShortIDs    []string
	ServerNames []string
	FallbackSNI string
}

// BuildRealityListener wraps `inner` with official `github.com/xtls/reality.NewListener`,
// providing genuine TLS 1.3 certificate-less handshake & active-probing forward camouflage.
func BuildRealityListener(inner net.Listener, opts RealityOptions) (net.Listener, error) {
	privBytes, err := decodeRealityPrivateKey(opts.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid REALITY X25519 private_key: %w", err)
	}
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("construct X25519 private key: %w", err)
	}

	sniList := opts.ServerNames
	if len(sniList) == 0 && opts.FallbackSNI != "" {
		for _, s := range strings.Split(opts.FallbackSNI, ",") {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				sniList = append(sniList, trimmed)
			}
		}
	}
	dest := strings.TrimSpace(opts.Dest)
	if dest == "" {
		if len(sniList) > 0 {
			dest = net.JoinHostPort(sniList[0], "443")
		} else {
			dest = "www.apple.com:443"
		}
	} else if _, _, splitErr := net.SplitHostPort(dest); splitErr != nil {
		dest = net.JoinHostPort(dest, "443")
	}

	serverNames := make(map[string]bool, max(len(sniList), 1))
	for _, s := range sniList {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			serverNames[trimmed] = true
		}
	}
	if len(serverNames) == 0 {
		host, _, err := net.SplitHostPort(dest)
		if err != nil || host == "" {
			host = "www.apple.com"
		}
		serverNames[host] = true
	}

	shortIDs := make(map[[8]byte]bool, max(len(opts.ShortIDs), 1))
	if len(opts.ShortIDs) == 0 {
		shortIDs[[8]byte{}] = true
	} else {
		for _, rawSID := range opts.ShortIDs {
			sid, err := parseShortIDHex(rawSID)
			if err != nil {
				return nil, err
			}
			shortIDs[sid] = true
		}
	}

	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	rcfg := &reality.Config{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
		Type:        "tcp",
		Dest:        dest,
		Xver:        0,
		ServerNames: serverNames,
		PrivateKey:  privKey,
		ShortIds:    shortIDs,
		MaxTimeDiff: 2 * time.Minute,
	}

	return reality.NewListener(inner, rcfg), nil
}

func decodeRealityPrivateKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty private key")
	}
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.StdEncoding,
	} {
		target := trimmed
		if enc == base64.URLEncoding || enc == base64.StdEncoding {
			target = s
		}
		if b, err := enc.DecodeString(target); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("expected 32-byte X25519 key (base64url/base64/hex)")
}

func parseShortIDHex(s string) ([8]byte, error) {
	var out [8]byte
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return out, nil
	}
	if len(s) > 16 {
		return out, fmt.Errorf("short_id %q exceeds 16 hex chars", s)
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid hex short_id %q: %w", s, err)
	}
	copy(out[:], decoded)
	return out, nil
}
