//go:build e2e

package e2e_test

import (
	"context"
	"os"
	"strings"
	"testing"
)

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
	accountID := strings.TrimPrefix(accountURL, h.GatewayURL+"/account/")
	ua, err := h.st.GetUpstreamAccountForAccount(context.Background(), "pebble", accountID)
	if err != nil {
		t.Fatalf("loading bound upstream account for %s: %v", accountID, err)
	}
	if ua == nil {
		t.Fatalf("no bound upstream account found for gateway account %s after order creation", accountID)
	}
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

		_, gatewayDNSValue, err := client.dns01TXTFromToken(dnsCh.Token)
		if err != nil {
			t.Fatalf("computing gateway dns-01 TXT value: %v", err)
		}
		keyAuth, dnsValue, err := dns01TXTFromTokenAndPEMKey(dnsCh.Token, []byte(ua.PrivateKey))
		if err != nil {
			t.Fatalf("computing upstream dns-01 TXT value: %v", err)
		}
		t.Logf("dns-01 TXT values: gateway=%s upstream=%s", gatewayDNSValue, dnsValue)

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

		// Wait until BIND is actually serving the TXT record before triggering Pebble.
		t.Logf("waiting for TXT record visibility in BIND...")
		waitForTXTRecordInBind(t, fqdn, dnsValue)

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
			t.Logf("pebble dns-01 authz status: url=%s status=%s", authzURL, a.Status)
			if a.Error != nil {
				t.Logf("pebble dns-01 authz error: type=%s detail=%s", a.Error.Type, a.Error.Detail)
			}
			for _, ch := range a.Challenges {
				if ch.Error != nil {
					t.Logf("pebble dns-01 challenge error: type=%s url=%s status=%s problemType=%s detail=%s", ch.Type, ch.URL, ch.Status, ch.Error.Type, ch.Error.Detail)
					continue
				}
				t.Logf("pebble dns-01 challenge status: type=%s url=%s status=%s", ch.Type, ch.URL, ch.Status)
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
