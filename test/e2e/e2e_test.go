//go:build e2e

// Package e2e_test contains the end-to-end suite that drives acme-gateway
// against real ACME servers (Pebble in Docker, and optionally Let's Encrypt
// staging). Shared helpers live here and in e2e_acmeclient_test.go /
// e2e_harness_test.go; the individual scenarios are split across
// e2e_pebble_test.go, e2e_dns01_test.go and e2e_staging_test.go.
package e2e_test

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	legocore "github.com/go-acme/lego/v4/challenge"
	legodns01 "github.com/go-acme/lego/v4/challenge/dns01"
	legoreg "github.com/go-acme/lego/v4/registration"
)

func init() {
	// testLogfFromLogger emits its own timestamp and component fields.
	log.SetFlags(0)
}

func testLogf(t *testing.T, component, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	t.Logf("ts=%s component=%s %s", time.Now().UTC().Format(time.RFC3339Nano), component, msg)
}

func testLogfFromLogger(component, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("ts=%s component=%s %s", time.Now().UTC().Format(time.RFC3339Nano), component, msg)
}

type legoE2EUser struct {
	Email        string
	PrivateKey   *ecdsa.PrivateKey
	Registration *legoreg.Resource
}

func (u *legoE2EUser) GetEmail() string {
	return u.Email
}

func (u *legoE2EUser) GetRegistration() *legoreg.Resource {
	return u.Registration
}

func (u *legoE2EUser) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}

type noopDNSProvider struct{}

func (p *noopDNSProvider) Present(domain, token, keyAuth string) error {
	return nil
}

func (p *noopDNSProvider) CleanUp(domain, token, keyAuth string) error {
	return nil
}

var _ legocore.Provider = (*noopDNSProvider)(nil)

type commandDNSProvider struct {
	presentCmd string
	cleanupCmd string
}

func (p *commandDNSProvider) Present(domain, token, keyAuth string) error {
	info := legodns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.TrimSuffix(info.EffectiveFQDN, ".")
	testLogfFromLogger("lego", "present fqdn=%s cmd=%s", fqdn, p.presentCmd)
	if err := runDNSHookCommand("present", p.presentCmd, fqdn, info.Value, token, keyAuth); err != nil {
		return err
	}
	timeout := envDurationSeconds("ACME_E2E_DNS_TIMEOUT_SECONDS", 300)
	interval := envDurationSeconds("ACME_E2E_DNS_POLL_SECONDS", 5)
	testLogfFromLogger("lego", "waiting for authoritative TXT visibility fqdn=%s timeout=%s interval=%s", fqdn, timeout, interval)
	if err := waitForAuthoritativeTXT(fqdn, info.Value, timeout, interval); err != nil {
		return err
	}
	return nil
}

func (p *commandDNSProvider) CleanUp(domain, token, keyAuth string) error {
	if strings.TrimSpace(p.cleanupCmd) == "" {
		testLogfFromLogger("lego", "cleanup skipped (ACME_E2E_DNS_CLEANUP_CMD unset)")
		return nil
	}
	info := legodns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.TrimSuffix(info.EffectiveFQDN, ".")
	testLogfFromLogger("lego", "cleanup fqdn=%s cmd=%s", fqdn, p.cleanupCmd)
	return runDNSHookCommand("cleanup", p.cleanupCmd, fqdn, info.Value, token, keyAuth)
}

func (p *commandDNSProvider) Timeout() (timeout, interval time.Duration) {
	return 5 * time.Minute, 5 * time.Second
}

var _ legocore.ProviderTimeout = (*commandDNSProvider)(nil)

func orderIDFromURL(t *testing.T, orderURL string) string {
	t.Helper()

	idx := strings.LastIndex(orderURL, "/")
	if idx < 0 || idx == len(orderURL)-1 {
		t.Fatalf("could not parse order ID from URL %q", orderURL)
	}
	return orderURL[idx+1:]
}

func envDurationSeconds(name string, defaultSeconds int) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return time.Duration(defaultSeconds) * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		panic(fmt.Sprintf("invalid %s=%q; expected positive integer seconds", name, v))
	}
	return time.Duration(n) * time.Second
}

// Ensure mustString is used (it is a utility referenced by future tests).
var _ = mustString
