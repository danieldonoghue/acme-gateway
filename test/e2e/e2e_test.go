//go:build e2e

package e2e_test

import (
	"os"
	"testing"
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

// TestStagingLE exercises the full flow against Let's Encrypt's staging
// environment. This test is skipped unless ACME_E2E_STAGING=1 is set.
//
// Prerequisites:
//   - A publicly reachable domain controlled by the tester.
//   - ACME_E2E_DOMAIN: the domain to request a certificate for.
//   - ACME_E2E_EMAIL:  contact email for the account.
//   - The gateway host must be reachable from the internet on port 80 for
//     HTTP-01 validation, OR use DNS-01 via an out-of-band hook (not automated
//     by this test).
//
// This test intentionally does NOT set up HTTP/DNS challenge handlers; it is a
// skeleton showing how to point the harness at staging. Full staging automation
// requires additional infrastructure outside the scope of this harness.
func TestStagingLE(t *testing.T) {
	if os.Getenv("ACME_E2E_STAGING") == "" {
		t.Skip("set ACME_E2E_STAGING=1 to run (requires internet access + real DNS)")
	}

	domain := os.Getenv("ACME_E2E_DOMAIN")
	if domain == "" {
		t.Fatal("ACME_E2E_DOMAIN must be set when running staging tests")
	}

	t.Logf("staging test targeting domain: %s", domain)
	t.Skip("staging test skeleton: full HTTP/DNS challenge handling not yet implemented")

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
