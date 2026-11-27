package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/logger"
)

type acmeDomainEntry struct {
	mgr     *autocert.Manager
	handler http.Handler
	refs    int
}

var (
	acmeHubMu    sync.RWMutex
	acmeManagers = make(map[string]*acmeDomainEntry)
	acmeServer   *http.Server
	acmeRefCnt   int
)

func registerACMEManager(domain, cacheDir string) *autocert.Manager {
	key := strings.ToLower(strings.TrimSpace(domain))
	acmeHubMu.Lock()
	ent := acmeManagers[key]
	if ent == nil {
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(key),
			Cache:      autocert.DirCache(cacheDir),
		}
		ent = &acmeDomainEntry{
			mgr:     mgr,
			handler: mgr.HTTPHandler(nil),
		}
		acmeManagers[key] = ent
	}
	ent.refs++
	mgr := ent.mgr
	acmeRefCnt++
	needStart := acmeServer == nil
	var srv *http.Server
	if needStart {
		srv = &http.Server{
			Addr: ":80",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				host = strings.ToLower(strings.TrimSpace(host))
				acmeHubMu.RLock()
				var h http.Handler
				if e := acmeManagers[host]; e != nil {
					h = e.handler
				} else {
					for _, cand := range acmeManagers {
						h = cand.handler
						break
					}
				}
				acmeHubMu.RUnlock()
				if h != nil {
					h.ServeHTTP(w, r)
					return
				}
				http.NotFound(w, r)
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		acmeServer = srv
	}
	acmeHubMu.Unlock()

	if needStart && srv != nil {
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Warnf("ACME HTTP-01 challenge listener (:80) stopped: %v", err)
			}
		}()
	}
	return mgr
}

func unregisterACMEManager(domain string) {
	key := strings.ToLower(strings.TrimSpace(domain))
	acmeHubMu.Lock()
	if ent := acmeManagers[key]; ent != nil {
		ent.refs--
		if ent.refs <= 0 {
			delete(acmeManagers, key)
		}
	}
	if acmeRefCnt > 0 {
		acmeRefCnt--
	}
	var srv *http.Server
	if acmeRefCnt == 0 && acmeServer != nil {
		srv = acmeServer
		acmeServer = nil
	}
	acmeHubMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// TLSProvider manages manual PEM reload, ACME HTTP-01 autocert, or ephemeral ECDSA P-256 certificates.
type TLSProvider struct {
	tlsConfig  *tls.Config
	acmeDomain string
}

func BuildTLSConfig(cfg *config.Config, serverName string) (*TLSProvider, error) {
	return BuildTLSConfigWithALPN(cfg, serverName, []string{"h2", "http/1.1"})
}

func BuildTLSConfigWithALPN(cfg *config.Config, serverName string, nextProtos []string) (*TLSProvider, error) {
	if len(nextProtos) == 0 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	domain := cfg.CertDomain
	if domain == "" {
		domain = serverName
	}
	if domain == "" {
		domain = "localhost"
	}

	// 1. Manual certificate files with hot mtime reload
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		reloader, err := newCertReloader(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		return &TLSProvider{
			tlsConfig: &tls.Config{
				MinVersion:     tls.VersionTLS12,
				GetCertificate: reloader.GetCertificate,
				NextProtos:     nextProtos,
			},
		}, nil
	}

	// 2. Built-in Let's Encrypt ACME HTTP-01 mode (`cert_mode=http`)
	if cfg.CertMode == "http" && domain != "" && domain != "localhost" {
		cacheDir := filepath.Join(filepath.Dir(cfg.RawPath), "certs")
		if cfg.RawPath == "" {
			cacheDir = "/etc/xoga/certs"
		}
		_ = os.MkdirAll(cacheDir, 0700)
		mgr := registerACMEManager(domain, cacheDir)
		tc := mgr.TLSConfig()
		tc.MinVersion = tls.VersionTLS12
		tc.NextProtos = append(tc.NextProtos, nextProtos...)
		return &TLSProvider{
			tlsConfig:  tc,
			acmeDomain: domain,
		}, nil
	}

	// 3. Fallback: generate ephemeral ECDSA P-256 certificate in memory (zero disk I/O)
	cert, err := generateSelfSignedCert(domain)
	if err != nil {
		return nil, err
	}
	logger.Infof("Using ephemeral ECDSA P-256 TLS certificate for SNI %q", domain)
	return &TLSProvider{
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			NextProtos:   nextProtos,
		},
	}, nil
}

func (p *TLSProvider) Config() *tls.Config {
	if p == nil {
		return nil
	}
	return p.tlsConfig
}

func (p *TLSProvider) Close() {
	if p != nil && p.acmeDomain != "" {
		unregisterACMEManager(p.acmeDomain)
		p.acmeDomain = ""
	}
}

type certReloader struct {
	certFile string
	keyFile  string
	mu       sync.RWMutex
	cert     *tls.Certificate
	modTime  time.Time
	lastChk  time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) reload() error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert = &pair
	r.modTime = st.ModTime()
	r.lastChk = time.Now()
	return nil
}

func (r *certReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	r.mu.RLock()
	c := r.cert
	needCheck := now.Sub(r.lastChk) > 60*time.Second
	r.mu.RUnlock()

	if !needCheck {
		return c, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastChk) > 60*time.Second {
		r.lastChk = now
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.modTime) {
			if pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile); err == nil {
				r.cert = &pair
				r.modTime = st.ModTime()
				logger.Infof("Reloaded updated TLS certificate from %s", r.certFile)
			}
		}
	}
	return r.cert, nil
}

func generateSelfSignedCert(commonName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
