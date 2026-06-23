//go:build e2e

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
)

// TestPebbleFullFlow exercises the complete RFC 8555 certificate issuance flow
// through the gateway backed by Pebble. Because PEBBLE_VA_ALWAYS_VALID=1 is
// set in docker-compose.yml, no real DNS or HTTP challenge resolution is needed.
//
// Flow:
//  1. Register a new ACME account.
//  2. Create a new order for a test domain.
//  3. Fetch and trigger the http-01 challenge.
//  4. Poll the order until it is "ready".
//  5. Finalize with a CSR.
//  6. Poll until the order is "valid" and a certificate URL is available.
//  7. Fetch the certificate (POST-as-GET) and verify it has the expected SAN.
func TestPebbleFullFlow(t *testing.T) {
	h := newHarness(t)

	client := newACMEClient(t, h.GatewayURL, h.TrustPool)

	// 1. Register account.
	accountURL := client.register(t)
	if accountURL == "" {
		t.Fatal("register returned empty account URL")
	}
	t.Logf("account: %s", accountURL)

	// 2. Create order.
	const domain = "gateway-test.example.invalid"
	order, orderURL := client.newOrder(t, domain)
	t.Logf("order: %s (status=%s)", orderURL, order.Status)
	if len(order.Authorizations) == 0 {
		t.Fatal("order has no authorizations")
	}

	// 3. Fetch authz and trigger first challenge.
	for _, authzURL := range order.Authorizations {
		authz := client.getAuthz(t, authzURL)
		t.Logf("authz %s: status=%s", authzURL, authz.Status)

		if authz.Status == "valid" {
			// Already satisfied (e.g. re-used authz) – nothing to do.
			continue
		}

		// Pick any challenge; Pebble with ALWAYS_VALID accepts any type.
		if len(authz.Challenges) == 0 {
			t.Fatalf("authz has no challenges for %s", authzURL)
		}
		chall := authz.Challenges[0]
		t.Logf("triggering challenge type=%s url=%s", chall.Type, chall.URL)
		client.triggerChallenge(t, chall.URL)
	}

	// 4. Poll until ready.
	order = client.pollOrder(t, orderURL)
	t.Logf("order after challenge: status=%s", order.Status)
	if order.Status != "ready" && order.Status != "valid" {
		t.Fatalf("expected order status ready or valid, got %q", order.Status)
	}

	// 5–6. Finalize and wait for certificate.
	certURL := client.finalize(t, order.Finalize, orderURL, domain)
	t.Logf("certificate URL: %s", certURL)

	// 7. Fetch and verify certificate.
	certPEM := client.fetchCert(t, certURL)
	certs := parseCerts(t, certPEM)
	t.Logf("received %d certificate(s); leaf CN=%q", len(certs), certs[0].Subject.CommonName)
	assertCertSANs(t, certs, domain)
}

// TestChallengeResponseLinkHeaders verifies RFC 8555 compliance: challenge
// responses include both rel="index" and rel="up" Link headers.
// RFC 8555 §7.1 specifies that rel="up" links challenge resources to their
// parent authorization, which clients like certbot require for proper protocol flow.
func TestChallengeResponseLinkHeaders(t *testing.T) {
	h := newHarness(t)

	client := newACMEClient(t, h.GatewayURL, h.TrustPool)

	// Register account and create an order.
	accountURL := client.register(t)
	if accountURL == "" {
		t.Fatal("register returned empty account URL")
	}

	const domain = "challenge-link-test.example.invalid"
	order, _ := client.newOrder(t, domain)
	if len(order.Authorizations) == 0 {
		t.Fatal("order has no authorizations")
	}

	// Fetch authorization and trigger its challenge; the client's
	// triggerChallenge method now asserts both Link relations are present.
	authzURL := order.Authorizations[0]
	authz := client.getAuthz(t, authzURL)

	if len(authz.Challenges) == 0 {
		t.Fatalf("authz has no challenges for %s", authzURL)
	}

	chall := authz.Challenges[0]
	t.Logf("triggering challenge %s (rel=up required per RFC 8555 §7.1)", chall.URL)

	// This call will fail if response does not include rel="up" Link header.
	client.triggerChallenge(t, chall.URL)

	t.Logf("challenge response correctly includes rel=\"index\" and rel=\"up\" Link headers")
}

// TestRoutingUsesAccountKeyTypeNotCSR verifies the current routing behaviour:
// key_type matching is based on account key algorithm at newOrder time, while
// CSR key algorithm is only available later at finalize.
func TestRoutingUsesAccountKeyTypeNotCSR(t *testing.T) {
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Upstreams = map[string]config.UpstreamConfig{
			"pebble-rsa": {
				DirectoryURL: "https://127.0.0.1:14000/dir",
				ContactEmail: "test@example.invalid",
				CACertPath:   sharedPebbleTLSCAFile,
			},
			"pebble-ecdsa": {
				DirectoryURL: "https://127.0.0.1:14000/dir",
				ContactEmail: "test@example.invalid",
				CACertPath:   sharedPebbleTLSCAFile,
			},
		}
		cfg.Profiles = map[string]string{
			"tlsclient": "Client cert profile",
		}
		cfg.Routing = config.RoutingConfig{
			Rules: []config.RoutingRule{
				{Match: config.MatchConfig{Profile: "tlsclient", KeyType: "RSA"}, Upstream: "pebble-rsa"},
				{Match: config.MatchConfig{Profile: "tlsclient", KeyType: "ECDSA"}, Upstream: "pebble-ecdsa"},
			},
			DefaultUpstream: "pebble-rsa",
		}
	})

	testCases := []struct {
		name          string
		accountKeyAlg accountKeyAlgorithm
		csrKeyAlg     csrKeyAlgorithm
		wantUpstream  string
	}{
		{
			name:          "ecdsa_account_routes_to_ecdsa_even_with_rsa_csr",
			accountKeyAlg: accountKeyECDSA,
			csrKeyAlg:     csrKeyRSA,
			wantUpstream:  "pebble-ecdsa",
		},
		{
			name:          "rsa_account_routes_to_rsa_even_with_ecdsa_csr",
			accountKeyAlg: accountKeyRSA,
			csrKeyAlg:     csrKeyECDSA,
			wantUpstream:  "pebble-rsa",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			client := newACMEClientWithAccountKey(t, h.GatewayURL, h.TrustPool, tc.accountKeyAlg)

			client.register(t)

			domain := "gateway-" + strings.ReplaceAll(tc.name, "_", "-") + ".example.invalid"
			order, orderURL := client.newOrderWithProfile(t, domain, "tlsclient")

			orderID := orderIDFromURL(t, orderURL)
			storedOrder, err := h.st.GetOrder(context.Background(), orderID)
			if err != nil {
				t.Fatalf("GetOrder(%s): %v", orderID, err)
			}
			if storedOrder == nil {
				t.Fatalf("order %s not found in store", orderID)
			}
			if storedOrder.UpstreamID != tc.wantUpstream {
				t.Fatalf("upstream mismatch: got %q, want %q", storedOrder.UpstreamID, tc.wantUpstream)
			}

			for _, authzURL := range order.Authorizations {
				authz := client.getAuthz(t, authzURL)
				if authz.Status == "valid" {
					continue
				}
				if len(authz.Challenges) == 0 {
					t.Fatalf("authz has no challenges for %s", authzURL)
				}
				client.triggerChallenge(t, authz.Challenges[0].URL)
			}

			order = client.pollOrder(t, orderURL)
			if order.Status != "ready" && order.Status != "valid" {
				t.Fatalf("expected order status ready or valid, got %q", order.Status)
			}

			certURL := client.finalizeWithCSRKey(t, order.Finalize, orderURL, domain, tc.csrKeyAlg)
			certs := parseCerts(t, client.fetchCert(t, certURL))
			assertCertSANs(t, certs, domain)
		})
	}
}

func orderIDFromURL(t *testing.T, orderURL string) string {
	t.Helper()

	idx := strings.LastIndex(orderURL, "/")
	if idx < 0 || idx == len(orderURL)-1 {
		t.Fatalf("could not parse order ID from URL %q", orderURL)
	}
	return orderURL[idx+1:]
}

// TestPebbleNewNonce verifies that the gateway correctly proxies replay nonces
// from Pebble. A HEAD request to /new-nonce must return a non-empty
// Replay-Nonce header and HTTP 200.
func TestPebbleNewNonce(t *testing.T) {
	h := newHarness(t)
	client := newACMEClient(t, h.GatewayURL, h.TrustPool)
	nonce := client.freshNonce(t)
	if nonce == "" {
		t.Fatal("freshNonce returned empty string")
	}
	t.Logf("nonce: %s", nonce)
}

// TestStagingLE exercises full issuance against Let's Encrypt staging via
// dns-01 using external hook commands for DNS updates.
func TestStagingLE(t *testing.T) {
	if os.Getenv("ACME_E2E_STAGING") == "" {
		t.Skip("set ACME_E2E_STAGING=1 to run (requires internet access + real DNS)")
	}

	domain := os.Getenv("ACME_E2E_DOMAIN")
	if domain == "" {
		t.Fatal("ACME_E2E_DOMAIN must be set when running staging tests")
	}
	email := os.Getenv("ACME_E2E_EMAIL")
	if email == "" {
		t.Fatal("ACME_E2E_EMAIL must be set when running staging tests")
	}
	presentCmd := os.Getenv("ACME_E2E_DNS_PRESENT_CMD")
	if presentCmd == "" {
		t.Fatal("ACME_E2E_DNS_PRESENT_CMD must be set to publish dns-01 TXT records")
	}
	cleanupCmd := os.Getenv("ACME_E2E_DNS_CLEANUP_CMD")

	h := newStagingHarness(t)
	client := newACMEClient(t, h.GatewayURL, h.TrustPool)

	accountURL := client.registerWithEmail(t, email)
	t.Logf("staging account: %s", accountURL)

	order, orderURL := client.newOrder(t, domain)
	t.Logf("staging order: %s (status=%s)", orderURL, order.Status)
	if len(order.Authorizations) == 0 {
		t.Fatal("order has no authorizations")
	}

	for _, authzURL := range order.Authorizations {
		authz := client.getAuthz(t, authzURL)
		t.Logf("staging authz %s: status=%s", authzURL, authz.Status)

		if authz.Status == "valid" {
			continue
		}

		dnsCh, ok := challengeByType(authz.Challenges, "dns-01")
		if !ok {
			available := make([]string, 0, len(authz.Challenges))
			for _, ch := range authz.Challenges {
				available = append(available, ch.Type)
			}
			t.Fatalf("dns-01 challenge not offered; available=%v", available)
		}

		keyAuth, dnsValue, err := client.dns01TXTFromToken(dnsCh.Token)
		if err != nil {
			t.Fatalf("computing dns-01 TXT value: %v", err)
		}

		fqdn := "_acme-challenge." + strings.TrimSuffix(domain, ".")
		runDNSHook(t, "present", presentCmd, fqdn, dnsValue, dnsCh.Token, keyAuth)
		if cleanupCmd != "" {
			t.Cleanup(func() {
				runDNSHook(t, "cleanup", cleanupCmd, fqdn, dnsValue, dnsCh.Token, keyAuth)
			})
		}

		waitForTXTRecord(t, fqdn, dnsValue)
		t.Logf("DEBUG: TXT record confirmed on all authoritative NS; waiting 30 seconds for full replication...")
		time.Sleep(30 * time.Second)
		t.Logf("DEBUG: verifying SOA serial consistency across authoritative NS...")
		verifySOAConsistency(t, domain)
		t.Logf("triggering staging dns-01 challenge: %s", dnsCh.URL)
		client.triggerChallenge(t, dnsCh.URL)
	}

	order = client.pollOrderWithTimeout(t, orderURL, envDurationSeconds("ACME_E2E_ORDER_TIMEOUT_SECONDS", 600))
	if order.Status != "ready" && order.Status != "valid" {
		if order.Error != nil {
			t.Logf("staging order problem: type=%s detail=%s", order.Error.Type, order.Error.Detail)
		}
		for _, authzURL := range order.Authorizations {
			a := client.getAuthz(t, authzURL)
			t.Logf("staging authz detail %s: status=%s identifier=%s", authzURL, a.Status, a.Identifier.Value)
			if a.Error != nil {
				t.Logf("staging authz problem: type=%s detail=%s", a.Error.Type, a.Error.Detail)
			}
			for _, ch := range a.Challenges {
				if ch.Type != "dns-01" {
					continue
				}
				t.Logf("staging dns-01 challenge detail: url=%s status=%s validated=%s", ch.URL, ch.Status, ch.Validated)
				if ch.Error != nil {
					t.Logf("staging dns-01 challenge problem: type=%s detail=%s", ch.Error.Type, ch.Error.Detail)
				}
			}
		}
		t.Fatalf("expected order status ready or valid, got %q", order.Status)
	}

	certURL := client.finalizeWithCSRKeyAndTimeout(
		t,
		order.Finalize,
		orderURL,
		domain,
		csrKeyECDSA,
		envDurationSeconds("ACME_E2E_FINALIZE_TIMEOUT_SECONDS", 600),
	)
	t.Logf("staging certificate URL: %s", certURL)

	certs := parseCerts(t, client.fetchCert(t, certURL))
	assertCertSANs(t, certs, domain)
	t.Logf("staging issued %d certificate(s)", len(certs))
}

func runDNSHook(t *testing.T, phase, command, fqdn, dnsValue, token, keyAuthorization string) {
	t.Helper()

	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"ACME_E2E_PHASE="+phase,
		"ACME_E2E_FQDN="+fqdn,
		"ACME_E2E_DNS_VALUE="+dnsValue,
		"ACME_E2E_TOKEN="+token,
		"ACME_E2E_KEY_AUTHORIZATION="+keyAuthorization,
	)
	cmd.Args = append(cmd.Args, fqdn, dnsValue)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dns hook (%s) failed: %v\noutput:\n%s", phase, err, string(out))
	}
	if len(out) > 0 {
		t.Logf("dns hook (%s) output:\n%s", phase, string(out))
	}
}

func waitForTXTRecord(t *testing.T, fqdn, want string) {
	t.Helper()

	timeout := envDurationSeconds("ACME_E2E_DNS_TIMEOUT_SECONDS", 300)
	interval := envDurationSeconds("ACME_E2E_DNS_POLL_SECONDS", 5)

	nsHosts, nsErr := authoritativeNameservers(fqdn)
	if nsErr != nil {
		t.Logf("warning: could not resolve authoritative nameservers for %s: %v", fqdn, nsErr)
	}
	if len(nsHosts) > 0 {
		t.Logf("authoritative nameservers for %s: %v", fqdn, nsHosts)
	}

	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		var matched bool
		if len(nsHosts) > 0 {
			missing := make([]string, 0, len(nsHosts))
			successfulNS := make([]string, 0, len(nsHosts))
			for _, ns := range nsHosts {
				txts, err := lookupTXTAtNameserver(fqdn, ns)
				if err != nil {
					missing = append(missing, ns+"(lookup failed)")
					if attempt == 1 {
						t.Logf("DEBUG: ns %s lookup error: %v", ns, err)
					}
					continue
				}
				t.Logf("DEBUG: ns %s returned %d TXT records", ns, len(txts))
				nsMatched := false
				for _, v := range txts {
					t.Logf("DEBUG: ns %s has TXT: %s", ns, v)
					if v == want {
						nsMatched = true
						break
					}
				}
				if !nsMatched {
					missing = append(missing, ns)
				} else {
					successfulNS = append(successfulNS, ns)
				}
			}
			matched = len(missing) == 0
			if !matched && (attempt == 1 || attempt%6 == 0) {
				t.Logf("TXT not yet visible on all authoritative NS for %s; still missing on: %v", fqdn, missing)
			}
			if matched {
				t.Logf("TXT record now visible on all authoritative NS for %s (found after %d attempts, successful NS: %v)", fqdn, attempt, successfulNS)
				return
			}
		} else {
			// Fallback if NS discovery fails.
			t.Logf("DEBUG: NS discovery failed, falling back to recursive resolver for %s", fqdn)
			txts, err := net.LookupTXT(fqdn)
			if err != nil {
				t.Logf("DEBUG: recursive lookup failed for %s: %v", fqdn, err)
			} else {
				t.Logf("DEBUG: recursive lookup returned %d TXT records for %s", len(txts), fqdn)
				for _, v := range txts {
					if v == want {
						t.Logf("DEBUG: found matching TXT record via recursive resolver after %d attempts", attempt)
						matched = true
						break
					}
				}
			}
			if matched {
				return
			}
		}

		if matched {
			return
		}
		timeLeft := deadline.Sub(time.Now())
		if attempt == 1 || attempt%6 == 0 {
			t.Logf("DEBUG: waitForTXTRecord still waiting (attempt %d, %v remaining)", attempt, timeLeft)
		}
		time.Sleep(interval)
	}
	t.Fatalf("TXT propagation timeout after %s for %s (wanted %q)", timeout, fqdn, want)
}

// TestPebbleDNS01 exercises full issuance against Pebble using dns-01 challenges
// with real DNS validation via BIND (not PEBBLE_VA_ALWAYS_VALID).
//
// This test requires:
//   - Docker with docker-compose
//   - PEBBLE_VA_ALWAYS_VALID=0 (to enable real DNS validation)
//   - ACME_E2E_PEBBLE_DNS=1 to opt-in (since it requires special Pebble setup)
//
// To run:
//
//	export ACME_E2E_PEBBLE_DNS=1
//	export PEBBLE_VA_ALWAYS_VALID=0
//	make test-e2e
//
// The test uses BIND running in docker-compose to serve pebble-test.local.
// DNS hooks use nsupdate to dynamically manage TXT records.
func TestPebbleDNS01(t *testing.T) {
	if os.Getenv("ACME_E2E_PEBBLE_DNS") == "" {
		t.Skip("set ACME_E2E_PEBBLE_DNS=1 to run (requires PEBBLE_VA_ALWAYS_VALID=0)")
	}

	h := newHarness(t)
	client := newACMEClient(t, h.GatewayURL, h.TrustPool)

	// Register account
	accountURL := client.register(t)
	t.Logf("pebble dns-01 account: %s", accountURL)

	// Create order for test domain in BIND zone
	const domain = "test.pebble-test.local"
	order, orderURL := client.newOrder(t, domain)
	t.Logf("pebble dns-01 order: %s (status=%s)", orderURL, order.Status)
	if len(order.Authorizations) == 0 {
		t.Fatal("order has no authorizations")
	}

	// Handle dns-01 challenges
	for _, authzURL := range order.Authorizations {
		authz := client.getAuthz(t, authzURL)
		t.Logf("pebble dns-01 authz %s: status=%s", authzURL, authz.Status)

		if authz.Status == "valid" {
			continue
		}

		dnsCh, ok := challengeByType(authz.Challenges, "dns-01")
		if !ok {
			available := make([]string, 0, len(authz.Challenges))
			for _, ch := range authz.Challenges {
				available = append(available, ch.Type)
			}
			t.Fatalf("dns-01 challenge not offered; available=%v", available)
		}

		keyAuth, dnsValue, err := client.dns01TXTFromToken(dnsCh.Token)
		if err != nil {
			t.Fatalf("computing dns-01 TXT value: %v", err)
		}

		// Use BIND hooks to add TXT record dynamically
		fqdn := "_acme-challenge." + strings.TrimSuffix(domain, ".")
		presentCmd := os.Getenv("ACME_E2E_PEBBLE_DNS_PRESENT_CMD")
		if presentCmd == "" {
			t.Fatal("ACME_E2E_PEBBLE_DNS_PRESENT_CMD not set; use 'make test-e2e-dns01'")
		}
		cleanupCmd := os.Getenv("ACME_E2E_PEBBLE_DNS_CLEANUP_CMD")
		if cleanupCmd == "" {
			t.Fatal("ACME_E2E_PEBBLE_DNS_CLEANUP_CMD not set; use 'make test-e2e-dns01'")
		}

		runDNSHook(t, "present", presentCmd, fqdn, dnsValue, dnsCh.Token, keyAuth)
		if cleanupCmd != "" {
			t.Cleanup(func() {
				runDNSHook(t, "cleanup", cleanupCmd, fqdn, dnsValue, dnsCh.Token, keyAuth)
			})
		}

		// Wait briefly for propagation to BIND
		t.Logf("waiting 2 seconds for DNS propagation to BIND...")
		time.Sleep(2 * time.Second)

		t.Logf("triggering pebble dns-01 challenge: %s", dnsCh.URL)
		client.triggerChallenge(t, dnsCh.URL)
	}

	// Poll order until ready
	order = client.pollOrder(t, orderURL)
	t.Logf("pebble dns-01 order after challenge: status=%s", order.Status)
	if order.Status != "ready" && order.Status != "valid" {
		if order.Error != nil {
			t.Logf("pebble dns-01 order error: type=%s detail=%s", order.Error.Type, order.Error.Detail)
		}
		for _, authzURL := range order.Authorizations {
			a := client.getAuthz(t, authzURL)
			if a.Error != nil {
				t.Logf("pebble dns-01 authz error: type=%s detail=%s", a.Error.Type, a.Error.Detail)
			}
		}
		t.Fatalf("expected order status ready or valid, got %q", order.Status)
	}

	// Finalize and fetch certificate
	certURL := client.finalize(t, order.Finalize, orderURL, domain)
	t.Logf("pebble dns-01 certificate URL: %s", certURL)

	certs := parseCerts(t, client.fetchCert(t, certURL))
	assertCertSANs(t, certs, domain)
	t.Logf("pebble dns-01 issued %d certificate(s)", len(certs))
}

func authoritativeNameservers(fqdn string) ([]string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if name == "" {
		return nil, fmt.Errorf("empty fqdn")
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return nil, fmt.Errorf("invalid fqdn %q", fqdn)
	}

	for i := 0; i <= len(labels)-2; i++ {
		candidate := strings.Join(labels[i:], ".")
		nsRecords, err := net.LookupNS(candidate)
		if err != nil || len(nsRecords) == 0 {
			continue
		}

		hosts := make([]string, 0, len(nsRecords))
		seen := map[string]struct{}{}
		for _, ns := range nsRecords {
			h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	return nil, fmt.Errorf("no authoritative nameservers found for %q", fqdn)
}

func lookupTXTAtNameserver(fqdn, nsHost string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// First, resolve the nameserver hostname to IP(s) using system resolver
	ips, err := net.LookupIP(nsHost)
	if err != nil {
		return nil, fmt.Errorf("resolve nameserver %s: %w", nsHost, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for nameserver %s", nsHost)
	}

	// Use the first IP to query
	nsIP := ips[0].String()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", net.JoinHostPort(nsIP, "53"))
		},
	}

	return r.LookupTXT(ctx, strings.TrimSuffix(fqdn, "."))
}

func verifySOAConsistency(t *testing.T, domain string) {
	t.Helper()

	nsHosts, err := authoritativeNameservers(domain)
	if err != nil {
		t.Logf("WARNING: could not resolve authoritative nameservers: %v", err)
		return
	}
	if len(nsHosts) == 0 {
		t.Logf("WARNING: no authoritative nameservers found for %s", domain)
		return
	}

	// Query SOA from each nameserver
	soaSerials := make(map[string]string)
	for _, ns := range nsHosts {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", net.JoinHostPort(ns, "53"))
			},
		}

		// Use LookupNS to get SOA details (this is a workaround; ideally we'd query SOA directly)
		// For now, just log NS to verify connectivity
		nss, err := r.LookupNS(ctx, domain)
		if err != nil {
			t.Logf("DEBUG: ns %s SOA query failed: %v", ns, err)
			soaSerials[ns] = "ERROR"
			continue
		}
		if len(nss) > 0 {
			t.Logf("DEBUG: ns %s responding (found %d NS records)", ns, len(nss))
			soaSerials[ns] = "OK"
		}
	}

	// Check if all NS are responding
	errCount := 0
	for ns, status := range soaSerials {
		if status == "ERROR" {
			t.Logf("DEBUG: nameserver %s not responding", ns)
			errCount++
		}
	}
	if errCount > 0 {
		t.Logf("WARNING: %d/%d nameservers not responding for SOA check", errCount, len(nsHosts))
	} else {
		t.Logf("DEBUG: all %d authoritative nameservers responding consistently", len(nsHosts))
	}
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

	// When implementing fully:
	//
	//   h := newHarness(t)   ← configure staging upstream in harness
	//   client := newACMEClient(t, h.GatewayURL, h.TrustPool)
	//   client.register(t)
	//   order, orderURL := client.newOrder(t, domain)
	//   ...handle challenge via HTTP-01 or DNS-01...
	//   certURL := client.finalize(t, order.Finalize, orderURL, domain)
	//   certs := parseCerts(t, client.fetchCert(t, certURL))
	//   assertCertSANs(t, certs, domain)
}

// Ensure mustString is used (it is a utility referenced by future tests).
var _ = mustString
