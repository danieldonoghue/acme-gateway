//go:build e2e

// Package e2e_test contains end-to-end tests for acme-gateway.
//
// Tests in this package start a real acme-gateway instance in-process and a
// Pebble ACME CA via Docker, then exercise the full RFC 8555 protocol flow.
//
// Running:
//
//	make test-e2e          # Pebble (fake CA, requires Docker)
//	make test-e2e-staging  # Let's Encrypt staging (requires internet + DNS setup)
//
// Prerequisites for Pebble tests:
//   - Docker with compose v2 (docker compose) available on PATH
//
// Prerequisites for staging tests:
//   - Set ACME_E2E_STAGING=1
//   - Set ACME_E2E_DOMAIN to a domain you control
//   - Set ACME_E2E_EMAIL to a contact email
//   - The domain's HTTP-01 challenge must be serveable: either run the test on
//     a host reachable from the internet on port 80, or configure DNS delegation
//     and set ACME_E2E_CHALLENGE=dns-01 with appropriate hook scripts.
package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/router"
	"github.com/danieldonoghue/acme-gateway/internal/server"
	"github.com/danieldonoghue/acme-gateway/internal/store"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

// harness holds the running infrastructure for a single test run.
type harness struct {
	GatewayURL   string
	TrustPool    *x509.CertPool // trusts gateway's self-signed cert
	pebbleCA     *x509.CertPool // trusts Pebble's CA (used when gateway talks upstream)
	pebbleCAFile string
	srv          *server.Server
	st           *store.Store
	tmpDir       string
}

// TestMain starts Pebble via Docker Compose and a gateway instance, runs all
// tests, then tears everything down.
func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "SKIP: docker not found on PATH; skipping e2e tests")
		return 0
	}

	// ── Start Pebble ──────────────────────────────────────────────────────────
	composeDir := "."
	up := exec.Command("docker", "compose", "-f", "docker-compose.yml", "up", "-d", "--wait")
	up.Dir = composeDir
	up.Stdout = os.Stderr
	up.Stderr = os.Stderr
	if err := up.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose up: %v\n", err)
		return 1
	}
	defer func() {
		down := exec.Command("docker", "compose", "-f", "docker-compose.yml", "down", "--remove-orphans")
		down.Dir = composeDir
		down.Run() //nolint:errcheck,gosec
	}()

	// ── Fetch Pebble root CA ─────────────────────────────────────────────────
	pebbleCAPool, pebbleCAPEM := waitForPebbleCA()
	if pebbleCAPool == nil {
		fmt.Fprintln(os.Stderr, "timed out waiting for Pebble CA cert")
		return 1
	}

	// ── Write Pebble CA to a temp file so the gateway can trust it ───────────
	tmpDir, err := os.MkdirTemp("", "acme-gateway-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	pebbleCAFile := filepath.Join(tmpDir, "pebble-ca.pem")
	if err := os.WriteFile(pebbleCAFile, pebbleCAPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "writing pebble CA: %v\n", err)
		return 1
	}

	// ── Build and stash the shared harness state ─────────────────────────────
	sharedPebbleCAPool = pebbleCAPool
	sharedPebbleCAFile = pebbleCAFile
	sharedTmpDir = tmpDir

	return m.Run()
}

// Package-level state shared across tests (set by TestMain).
var (
	sharedPebbleCAPool *x509.CertPool
	sharedPebbleCAFile string
	sharedTmpDir       string
)

// newHarness starts a fresh gateway instance for a single test.
// The caller must call h.Close() when done (use t.Cleanup).
func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()

	// ── Self-signed TLS cert for the gateway ──────────────────────────────────
	certPEM, keyPEM, err := selfSignedCert()
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	trustPool := x509.NewCertPool()
	trustPool.AppendCertsFromPEM(certPEM)

	// ── Bind a random port ────────────────────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", port)

	// ── Build config ──────────────────────────────────────────────────────────
	dbPath := filepath.Join(dir, "state.db")
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:  ln.Addr().String(),
			BaseURL: baseURL,
		},
		State: config.StateConfig{DBPath: dbPath},
		Bootstrap: config.BootstrapConfig{
			Enabled:  false,
			CertPath: certPath,
			KeyPath:  keyPath,
		},
		Upstreams: map[string]config.UpstreamConfig{
			"pebble": {
				DirectoryURL: "https://127.0.0.1:14000/dir",
				ContactEmail: "test@example.invalid",
				CACertPath:   sharedPebbleCAFile,
			},
		},
		Routing: config.RoutingConfig{
			DefaultUpstream: "pebble",
		},
	}

	// ── Initialise gateway components ─────────────────────────────────────────
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := router.New(&cfg.Routing)
	pool := upstream.NewPool(cfg, st)
	h := server.NewHandler(cfg, st, r, pool, log)
	srv := server.NewServer(h, log)

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	srv.SetCertificate(&tlsCert)

	// ── Start server ──────────────────────────────────────────────────────────
	go srv.ServeListener(ln) //nolint:errcheck

	// ── Wait for gateway to accept connections ────────────────────────────────
	probe := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
		Timeout:   time.Second,
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := probe.Get(baseURL + "/directory"); err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	h2 := &harness{
		GatewayURL:   baseURL,
		TrustPool:    trustPool,
		pebbleCA:     sharedPebbleCAPool,
		pebbleCAFile: sharedPebbleCAFile,
		srv:          srv,
		st:           st,
		tmpDir:       dir,
	}
	t.Cleanup(h2.close)
	return h2
}

func (h *harness) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h.srv.Shutdown(ctx) //nolint:errcheck,gosec
	h.st.Close()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// waitForPebbleCA polls Pebble's management API until it returns a root CA cert
// or the 30-second deadline is exceeded. Returns the cert pool and raw PEM.
func waitForPebbleCA() (*x509.CertPool, []byte) {
	insecure := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // bootstrapping trust, test-only
		},
		Timeout: 3 * time.Second,
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := insecure.Get("https://127.0.0.1:15000/roots/0")
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(body) > 0 {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(body) {
				return pool, body
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, nil
}

// selfSignedCert generates an ECDSA P-256 self-signed certificate for 127.0.0.1
// valid for 24 hours.
func selfSignedCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme-gateway-test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
