package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// DNSHook executes operator-supplied scripts to deploy and clean up dns-01
// challenge TXT records. The scripts receive the same environment variables
// as Certbot DNS manual hooks.
type DNSHook struct {
	deployScript  string
	cleanupScript string
}

// NewDNSHook creates a DNSHook with the given script paths.
func NewDNSHook(deployScript, cleanupScript string) *DNSHook {
	return &DNSHook{deployScript: deployScript, cleanupScript: cleanupScript}
}

// Deploy executes the deploy script to provision the DNS TXT record.
// Environment variables set:
//   - CERTBOT_DOMAIN      – the domain being validated
//   - CERTBOT_VALIDATION  – the TXT record value
//   - CERTBOT_TOKEN       – the challenge token
func (h *DNSHook) Deploy(ctx context.Context, domain, validation, token string) error {
	if h.deployScript == "" {
		return fmt.Errorf("dns_hook.deploy_script is not configured")
	}
	return h.runScript(ctx, h.deployScript, domain, validation, token)
}

// Cleanup executes the cleanup script to remove the DNS TXT record.
func (h *DNSHook) Cleanup(ctx context.Context, domain, validation, token string) error {
	if h.cleanupScript == "" {
		return nil // cleanup is optional
	}
	return h.runScript(ctx, h.cleanupScript, domain, validation, token)
}

func (h *DNSHook) runScript(ctx context.Context, script, domain, validation, token string) error {
	// Allow up to 2 minutes for the hook to complete.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, script) //nolint:gosec
	cmd.Env = append(os.Environ(),
		"CERTBOT_DOMAIN="+domain,
		"CERTBOT_VALIDATION="+validation,
		"CERTBOT_TOKEN="+token,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hook %q failed: %w\noutput: %s", script, err, string(out))
	}
	return nil
}

// DNSTXT computes the base64url(SHA-256(keyAuthorization)) value that must be
// placed in the _acme-challenge TXT record for a dns-01 challenge.
func DNSTXT(keyAuthorization string) (string, error) {
	if keyAuthorization == "" {
		return "", fmt.Errorf("empty key authorisation")
	}
	sum := sha256.Sum256([]byte(keyAuthorization))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
