// Package bootstrap handles automatic acquisition and renewal of the gateway's
// own TLS certificate using a dns-01 ACME challenge via hook scripts.
package bootstrap

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
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

const renewCheckInterval = 12 * time.Hour

// Manager acquires and renews the gateway's own TLS certificate.
type Manager struct {
	cfg     *config.BootstrapConfig
	upCfg   *config.UpstreamConfig
	log     *slog.Logger
	onRenew func(*tls.Certificate)
}

// NewManager creates a bootstrap Manager.
// onRenew is called whenever a new certificate is loaded (initial + renewals);
// the caller should call Server.SetCertificate inside onRenew.
func NewManager(cfg *config.BootstrapConfig, upCfg *config.UpstreamConfig, log *slog.Logger, onRenew func(*tls.Certificate)) *Manager {
	return &Manager{cfg: cfg, upCfg: upCfg, log: log, onRenew: onRenew}
}

// Bootstrap checks for an existing valid certificate and either loads it or
// acquires a new one. Must be called before the HTTPS listener starts.
// Returns the loaded TLS certificate.
func (m *Manager) Bootstrap(ctx context.Context) (*tls.Certificate, error) {
	cert, err := m.loadExistingCert()
	if err == nil && cert != nil && !m.isExpiringSoon(cert) {
		m.log.Info("bootstrap: loaded existing certificate",
			"domain", m.cfg.Domain,
			"not_after", x509LeafNotAfter(cert),
		)
		return cert, nil
	}

	m.log.Info("bootstrap: acquiring new certificate", "domain", m.cfg.Domain)
	if err := m.acquire(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap acquire: %w", err)
	}

	cert, err = m.loadExistingCert()
	if err != nil {
		return nil, fmt.Errorf("loading certificate after acquire: %w", err)
	}
	return cert, nil
}

// StartRenewalLoop starts a background goroutine that checks certificate
// expiry every 12 hours and renews when within renew_before_days.
func (m *Manager) StartRenewalLoop(ctx context.Context, initial *tls.Certificate) {
	go m.renewalLoop(ctx, initial)
}

func (m *Manager) renewalLoop(ctx context.Context, current *tls.Certificate) {
	ticker := time.NewTicker(renewCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if m.isExpiringSoon(current) {
				m.log.Info("bootstrap: certificate expiring soon, renewing", "domain", m.cfg.Domain)
				if err := m.acquire(ctx); err != nil {
					m.log.Error("bootstrap: renewal failed", "err", err)
					continue
				}
				cert, err := m.loadExistingCert()
				if err != nil {
					m.log.Error("bootstrap: loading renewed certificate failed", "err", err)
					continue
				}
				current = cert
				m.log.Info("bootstrap: certificate renewed", "domain", m.cfg.Domain, "not_after", x509LeafNotAfter(cert))
				if m.onRenew != nil {
					m.onRenew(cert)
				}
			}
		}
	}
}

// acquire runs the full dns-01 ACME flow to obtain a certificate.
func (m *Manager) acquire(ctx context.Context) error {
	// Generate a private key for the certificate (separate from the ACME account key).
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating certificate key: %w", err)
	}

	// Load or create a persistent ACME account key so renewals reuse the same account.
	accountKey, err := m.loadOrCreateAccountKey()
	if err != nil {
		return fmt.Errorf("loading bootstrap account key: %w", err)
	}

	// Create an upstream ACME client using the persisted account key.
	client, err := upstream.New(m.upCfg.DirectoryURL, accountKey)
	if err != nil {
		return fmt.Errorf("creating ACME client: %w", err)
	}

	// Reuse a saved account URL, or register and persist a new one.
	// Guard: only use the saved URL if it looks like a valid URL; a corrupt/empty
	// file would otherwise cause every upstream call to fail with KID errors.
	accountURLPath := m.accountKeyPath() + ".url"
	savedURL := ""
	if data, err := os.ReadFile(accountURLPath); err == nil {
		u := strings.TrimSpace(string(data))
		if p, err := url.Parse(u); err == nil && p.Scheme == "https" && p.Host != "" {
			savedURL = u
		}
	}
	if savedURL != "" {
		client.SetAccountURL(savedURL)
	} else {
		accountURL, err := client.Register(ctx, m.upCfg.ContactEmail, m.upCfg.EAB)
		if err != nil {
			return fmt.Errorf("registering bootstrap account: %w", err)
		}
		if err := atomicWrite(accountURLPath, []byte(accountURL), 0600); err != nil {
			m.log.Warn("bootstrap: could not persist account URL", "err", err)
		}
	}

	// Submit order.
	ids := []upstream.Identifier{{Type: "dns", Value: m.cfg.Domain}}
	order, orderURL, err := client.SubmitOrder(ctx, ids, "")
	if err != nil {
		return fmt.Errorf("submitting bootstrap order: %w", err)
	}
	_ = orderURL

	if len(order.Authorizations) == 0 {
		return fmt.Errorf("upstream returned no authorizations")
	}

	// Process each authorization.
	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("getting authorization: %w", err)
		}

		if authz.Status == "valid" {
			continue
		}

		// Find the dns-01 challenge.
		var dns01Chal *upstream.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == "dns-01" {
				dns01Chal = &authz.Challenges[i]
				break
			}
		}
		if dns01Chal == nil {
			return fmt.Errorf("no dns-01 challenge found for %s", authz.Identifier.Value)
		}

		// Run the deploy hook.
		hook := NewDNSHook(m.cfg.DNSHook.DeployScript, m.cfg.DNSHook.CleanupScript)
		keyAuth, err := client.KeyAuthorization(dns01Chal.Token)
		if err != nil {
			return fmt.Errorf("computing key authorisation: %w", err)
		}
		validation, err := DNSTXT(keyAuth)
		if err != nil {
			return fmt.Errorf("computing DNS TXT value: %w", err)
		}

		if err := hook.Deploy(ctx, authz.Identifier.Value, validation, dns01Chal.Token); err != nil {
			return fmt.Errorf("DNS deploy hook: %w", err)
		}

		// Notify upstream the challenge is ready.
		if _, err := client.TriggerChallenge(ctx, dns01Chal.URL); err != nil {
			hook.Cleanup(ctx, authz.Identifier.Value, validation, dns01Chal.Token) //nolint:errcheck,gosec
			return fmt.Errorf("triggering challenge: %w", err)
		}

		// Poll for the authorization to become valid (up to 5 minutes).
		if err := pollAuthorization(ctx, client, authzURL); err != nil {
			hook.Cleanup(ctx, authz.Identifier.Value, validation, dns01Chal.Token) //nolint:errcheck,gosec
			return err
		}

		hook.Cleanup(ctx, authz.Identifier.Value, validation, dns01Chal.Token) //nolint:errcheck,gosec
	}

	// Build the CSR.
	csrDER, err := buildCSR(certKey, m.cfg.Domain)
	if err != nil {
		return fmt.Errorf("building CSR: %w", err)
	}

	// Finalize.
	finalOrder, err := client.FinalizeOrder(ctx, order.Finalize, csrDER)
	if err != nil {
		return fmt.Errorf("finalizing order: %w", err)
	}

	// Wait for the order to become valid.
	if finalOrder.Status != "valid" {
		if err := pollOrder(ctx, client, orderURL); err != nil {
			return err
		}
		finalOrder, err = client.GetOrder(ctx, orderURL)
		if err != nil {
			return err
		}
	}

	if finalOrder.Certificate == "" {
		return fmt.Errorf("order is valid but no certificate URL returned")
	}

	// Fetch the certificate chain.
	chain, err := client.FetchCertificate(ctx, finalOrder.Certificate)
	if err != nil {
		return fmt.Errorf("fetching certificate: %w", err)
	}

	// Write key and cert to disk.
	certKeyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: certKeyDER})

	if err := atomicWrite(m.cfg.KeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}
	if err := atomicWrite(m.cfg.CertPath, chain, 0644); err != nil {
		return fmt.Errorf("writing cert: %w", err)
	}

	m.log.Info("bootstrap: certificate written",
		"cert_path", m.cfg.CertPath,
		"key_path", m.cfg.KeyPath,
	)
	return nil
}

// loadExistingCert loads the certificate and key from disk if they exist.
func (m *Manager) loadExistingCert() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(m.cfg.CertPath, m.cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// isExpiringSoon returns true if the certificate expires within renew_before_days.
func (m *Manager) isExpiringSoon(cert *tls.Certificate) bool {
	notAfter := x509LeafNotAfter(cert)
	if notAfter.IsZero() {
		return true
	}
	renewBefore := time.Duration(m.cfg.RenewBeforeDays) * 24 * time.Hour
	return time.Until(notAfter) < renewBefore
}

// x509LeafNotAfter extracts the NotAfter from the leaf certificate.
func x509LeafNotAfter(cert *tls.Certificate) time.Time {
	if cert == nil || len(cert.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// buildCSR creates a DER-encoded CSR for the given domain and key.
func buildCSR(key *ecdsa.PrivateKey, domain string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	return x509.CreateCertificateRequest(rand.Reader, tpl, key)
}

// atomicWrite writes data to path atomically using a temp file + rename.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()          //nolint:errcheck,gosec
		os.Remove(tmpPath) //nolint:errcheck,gosec
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()          //nolint:errcheck,gosec
		os.Remove(tmpPath) //nolint:errcheck,gosec
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath) //nolint:errcheck,gosec
		return err
	}
	return os.Rename(tmpPath, path)
}

// pollAuthorization polls the authorization URL until it reaches "valid" or "invalid".
func pollAuthorization(ctx context.Context, client *upstream.Client, authzURL string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}
		switch authz.Status {
		case "valid":
			return nil
		case "invalid":
			return fmt.Errorf("authorization became invalid")
		}
	}
	return fmt.Errorf("authorization did not become valid within timeout")
}

// pollOrder polls the order URL until it reaches "valid" status.
func pollOrder(ctx context.Context, client *upstream.Client, orderURL string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
		order, err := client.GetOrder(ctx, orderURL)
		if err != nil {
			return err
		}
		switch order.Status {
		case "valid":
			return nil
		case "invalid":
			return fmt.Errorf("order became invalid")
		}
	}
	return fmt.Errorf("order did not become valid within timeout")
}

// accountKeyPath returns the path where the bootstrap ACME account key is stored,
// placed adjacent to the gateway certificate key file.
func (m *Manager) accountKeyPath() string {
	return filepath.Join(filepath.Dir(m.cfg.KeyPath), "bootstrap-account.key")
}

// loadOrCreateAccountKey loads the bootstrap ACME account key from disk.
// If no key file exists, a new P-256 key is generated and persisted.
func (m *Manager) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	path := m.accountKeyPath()
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating bootstrap account key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling bootstrap account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := atomicWrite(path, pemData, 0600); err != nil {
		return nil, fmt.Errorf("writing bootstrap account key: %w", err)
	}
	return key, nil
}
