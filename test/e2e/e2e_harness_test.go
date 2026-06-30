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
//     and set ACME_E2E_CHALLENGE=dns-01 with appropriate hook commands
//     (compiled binaries from acme-gateway-hooks are preferred).
package e2e_test

import (
	"bytes"
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
	"strconv"
	"strings"
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
	if os.Getenv("ACME_E2E_STAGING") != "" {
		// Staging tests run against Let's Encrypt over the public internet and do
		// not require Pebble or Docker.
		return m.Run()
	}

	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "SKIP: docker not found on PATH; skipping e2e tests")
		return 0
	}

	// ── Start Pebble ──────────────────────────────────────────────────────────
	composeDir := "."
	args := []string{"compose", "-f", "docker-compose.yml"}

	// Add profile if specified (ACME_E2E_COMPOSE_PROFILE env var)
	// Profiles: "always-valid" for standard tests, "dns-challenge" for DNS-01 tests
	if profile := os.Getenv("ACME_E2E_COMPOSE_PROFILE"); profile != "" {
		args = append(args, "--profile", profile)
	}
	args = append(args, "up", "-d")

	up := exec.Command("docker", args...)
	up.Dir = composeDir
	up.Stdout = os.Stderr
	up.Stderr = os.Stderr
	if err := up.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "docker compose up: %v\n", err)
		return 1
	}
	defer func() {
		args := []string{"compose", "-f", "docker-compose.yml"}
		if profile := os.Getenv("ACME_E2E_COMPOSE_PROFILE"); profile != "" {
			args = append(args, "--profile", profile)
		}
		args = append(args, "down", "--remove-orphans")
		down := exec.Command("docker", args...)
		down.Dir = composeDir
		down.Run() //nolint:errcheck,gosec
	}()

	// ── Fetch Pebble root CA (for verifying issued certificates) ────────────
	pebbleCAPool, pebbleCAPEM := waitForPebbleCA()
	if pebbleCAPool == nil {
		fmt.Fprintln(os.Stderr, "timed out waiting for Pebble CA cert")
		return 1
	}

	// ── Extract Pebble's TLS server cert (minica root CA for port 14000) ────
	// Pebble's ACME endpoint (port 14000) is served with a minica-signed TLS
	// cert that is distinct from the ACME issuance CA. Copy the root from the
	// well-known path inside the container so the gateway can trust it.
	tmpDir, err := os.MkdirTemp("", "acme-gateway-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	// Resolve the container ID via compose so we are not coupled to the
	// generated name (which varies with COMPOSE_PROJECT_NAME, working dir, etc.).
	// Try "pebble-dns" first (dns-challenge profile), then "pebble" (always-valid profile).
	var pebbleContainerID string
	for _, service := range []string{"pebble-dns", "pebble"} {
		psOut, err := exec.CommandContext(context.Background(),
			"docker", "compose", "-f", "docker-compose.yml", "ps", "-q", service,
		).Output()
		if err == nil && len(bytes.TrimSpace(psOut)) > 0 {
			pebbleContainerID = string(bytes.TrimSpace(psOut))
			break
		}
	}
	if pebbleContainerID == "" {
		fmt.Fprintf(os.Stderr, "resolving pebble container ID: no pebble service running\n")
		return 1
	}

	pebbleTLSCAFile := filepath.Join(tmpDir, "pebble-tls-ca.pem")
	cpCmd := exec.Command("docker", "cp", pebbleContainerID+":/test/certs/pebble.minica.pem", pebbleTLSCAFile)
	cpCmd.Stdout = os.Stderr
	cpCmd.Stderr = os.Stderr
	if err := cpCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "docker cp pebble TLS CA: %v\n", err)
		return 1
	}

	pebbleCAFile := filepath.Join(tmpDir, "pebble-ca.pem")
	if err := os.WriteFile(pebbleCAFile, pebbleCAPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "writing pebble CA: %v\n", err)
		return 1
	}

	// ── Build and stash the shared harness state ─────────────────────────────
	sharedPebbleCAPool = pebbleCAPool
	sharedPebbleCAFile = pebbleCAFile
	sharedPebbleTLSCAFile = pebbleTLSCAFile
	sharedTmpDir = tmpDir

	return m.Run()
}

// Package-level state shared across tests (set by TestMain).
var (
	sharedPebbleCAPool    *x509.CertPool
	sharedPebbleCAFile    string
	sharedPebbleTLSCAFile string // TLS CA for Pebble's ACME endpoint (port 14000)
	sharedTmpDir          string
)

// newHarness starts a fresh gateway instance for a single test.
// The caller must call h.Close() when done (use t.Cleanup).
func newHarness(t *testing.T) *harness {
	t.Helper()

	return newHarnessWithConfig(t, nil)
}

// newHarnessWithConfig starts a fresh gateway and allows callers to mutate the
// in-memory config before components are initialised.
func newHarnessWithConfig(t *testing.T, mutate func(*config.Config)) *harness {
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
				CACertPath:   sharedPebbleTLSCAFile,
			},
		},
		Routing: config.RoutingConfig{
			DefaultUpstream: "pebble",
		},
	}
	if mutate != nil {
		mutate(cfg)
	}

	// ── Initialise gateway components ─────────────────────────────────────────
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("component", "acme-gateway")
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

func newStagingHarness(t *testing.T) *harness {
	t.Helper()

	email := os.Getenv("ACME_E2E_EMAIL")
	if email == "" {
		email = "test@example.com" // fallback for tests that don't set it
	}
	presentCmd := strings.TrimSpace(os.Getenv("ACME_E2E_DNS_PRESENT_CMD"))
	if presentCmd == "" {
		t.Fatal("ACME_E2E_DNS_PRESENT_CMD must be set when running staging tests")
	}
	cleanupCmd := strings.TrimSpace(os.Getenv("ACME_E2E_DNS_CLEANUP_CMD"))

	presentWrapper := writeDNSHookWrapper(t, presentCmd, "present")
	cleanupWrapper := ""
	if cleanupCmd != "" {
		cleanupWrapper = writeDNSHookWrapper(t, cleanupCmd, "cleanup")
	}

	// Mirror the production settle delay: after the gateway's authoritative
	// quorum is reached, wait before triggering the CA so lagging anycast nodes
	// (which the CA's resolver may hit) have time to converge. The parent zone
	// converges slowly, so without this the gateway triggers the CA the instant
	// it sees its own record and validation can hit a node that is still behind
	// (transient NXDOMAIN). Override with ACME_E2E_DNS_SETTLE_SECONDS.
	settleSeconds := 20
	if v := strings.TrimSpace(os.Getenv("ACME_E2E_DNS_SETTLE_SECONDS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			t.Fatalf("invalid ACME_E2E_DNS_SETTLE_SECONDS=%q: want a non-negative integer", v)
		}
		settleSeconds = n
	}

	// Optional CNAME delegation. When EXCEDO_DNS_ZONE is set, the dns hook
	// publishes challenge TXTs into that dedicated zone, so the gateway must
	// follow the _acme-challenge.<domain> CNAME to the delegated target. The
	// excedo hook reads EXCEDO_DNS_ZONE itself from the inherited environment;
	// here we just enable the gateway-side delegation resolution. Unset = off
	// (records published at _acme-challenge.<domain> in the source zone).
	var delegation config.DNSDelegationPolicy
	if zone := strings.Trim(strings.TrimSpace(os.Getenv("EXCEDO_DNS_ZONE")), "."); zone != "" {
		enabled := true
		delegation = config.DNSDelegationPolicy{
			Enabled:             &enabled,
			Mode:                "strict",
			AllowedZoneSuffixes: []string{zone}, // no leading dot; matcher adds it
		}
		t.Logf("dns-01 delegation enabled for e2e: zone=%s", zone)
	}

	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Upstreams = map[string]config.UpstreamConfig{
			"le-staging": {
				DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
				ContactEmail: email,
				DNSHook: config.DNSHook{
					DeployScript:  presentWrapper,
					CleanupScript: cleanupWrapper,
					Propagation: config.DNSPropagationPolicy{
						SettleSeconds: settleSeconds,
					},
					Delegation: delegation,
				},
			},
		}
		cfg.Routing = config.RoutingConfig{DefaultUpstream: "le-staging"}
	})
}

func newStagingHarnessNoGatewayDNSHooks(t *testing.T) *harness {
	t.Helper()

	email := os.Getenv("ACME_E2E_EMAIL")
	if email == "" {
		email = "test@example.com"
	}

	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Upstreams = map[string]config.UpstreamConfig{
			"le-staging": {
				DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
				ContactEmail: email,
			},
		}
		cfg.Routing = config.RoutingConfig{DefaultUpstream: "le-staging"}
	})
}

func writeDNSHookWrapper(t *testing.T, command, phase string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "dns-hook-wrapper-"+phase+".sh")
	content := strings.Join([]string{
		"#!/bin/sh",
		"set -e",
		"",
		"# Bridge gateway hook env vars to ACME_E2E_* command inputs.",
		"export ACME_E2E_PHASE=\"" + phase + "\"",
		"export ACME_E2E_FQDN=\"${ACME_GATEWAY_FQDN:-${CERTBOT_DOMAIN:-}}\"",
		"export ACME_E2E_DNS_VALUE=\"${ACME_GATEWAY_DNS_VALUE:-${CERTBOT_VALIDATION:-}}\"",
		"export ACME_E2E_TOKEN=\"${ACME_GATEWAY_TOKEN:-${CERTBOT_TOKEN:-}}\"",
		"",
		"# Forward positional args from gateway. Drop the optional leading \"--\"",
		"# sentinel so command wrappers still receive fqdn as $1 and value as $2.",
		"if [ \"${1:-}\" = \"--\" ]; then",
		"  shift",
		"fi",
		command + " \"$@\"",
		"",
		"# No post-deploy sleep: the gateway's own dns_hook.propagation gate waits",
		"# for authoritative convergence before triggering the upstream challenge.",
		"# A wrapper sleep here would double the propagation wait.",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writing dns hook wrapper: %v", err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod dns hook wrapper: %v", err)
	}
	return path
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
