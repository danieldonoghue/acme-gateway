//go:build e2e

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	legocrypto "github.com/go-acme/lego/v4/certcrypto"
	legocert "github.com/go-acme/lego/v4/certificate"
	legodns01 "github.com/go-acme/lego/v4/challenge/dns01"
	legoapi "github.com/go-acme/lego/v4/lego"
	legoreg "github.com/go-acme/lego/v4/registration"
)

// TestStagingLE exercises full issuance against Let's Encrypt staging via
// dns-01 with gateway-managed upstream DNS hooks.
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
	h := newStagingHarness(t)
	client := newACMEClient(t, h.GatewayURL, h.TrustPool)

	accountURL := client.registerWithEmail(t, email)
	testLogf(t, "test", "staging account: %s", accountURL)
	accountID := strings.TrimPrefix(accountURL, h.GatewayURL+"/account/")

	order, orderURL := client.newOrder(t, domain)
	testLogf(t, "test", "staging order: %s (status=%s)", orderURL, order.Status)
	ua, err := h.st.GetUpstreamAccountForAccount(context.Background(), "le-staging", accountID)
	if err != nil {
		t.Fatalf("loading bound upstream account for %s: %v", accountID, err)
	}
	if ua == nil {
		t.Fatalf("no bound upstream account found for gateway account %s after order creation", accountID)
	}
	if len(order.Authorizations) == 0 {
		t.Fatal("order has no authorizations")
	}

	for _, authzURL := range order.Authorizations {
		authz := client.getAuthz(t, authzURL)
		testLogf(t, "test", "staging authz %s: status=%s", authzURL, authz.Status)

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

		keyAuth, dnsValue, err := dns01TXTFromTokenAndPEMKey(dnsCh.Token, []byte(ua.PrivateKey))
		if err != nil {
			t.Fatalf("computing upstream dns-01 TXT value: %v", err)
		}

		fqdn := "_acme-challenge." + strings.TrimSuffix(domain, ".")
		_ = keyAuth // kept for parity with debug workflows where key auth is inspected

		testLogf(t, "test", "triggering staging dns-01 challenge: %s", dnsCh.URL)
		client.triggerChallenge(t, dnsCh.URL)

		// In staging, gateway-managed hook deployment runs as part of challenge
		// trigger handling, so propagation checks must happen after trigger.
		// Cleanup runs asynchronously and will complete in the background.
		found := waitForTXTRecord(t, fqdn, dnsValue)
		if found {
			testLogf(t, "test", "TXT record confirmed on all authoritative NS; waiting 30 seconds for full replication...")
			time.Sleep(30 * time.Second)
			testLogf(t, "test", "verifying SOA serial consistency across authoritative NS...")
			verifySOAConsistency(t, domain)
		} else {
			testLogf(t, "test", "DNS check timed out or failed (proceeding anyway)")
		}
	}

	order = client.pollOrderWithTimeout(t, orderURL, envDurationSeconds("ACME_E2E_ORDER_TIMEOUT_SECONDS", 600))
	if order.Status != "ready" && order.Status != "valid" {
		if order.Error != nil {
			testLogf(t, "test", "staging order problem: type=%s detail=%s", order.Error.Type, order.Error.Detail)
		}
		for _, authzURL := range order.Authorizations {
			a := client.getAuthz(t, authzURL)
			testLogf(t, "test", "staging authz detail %s: status=%s identifier=%s", authzURL, a.Status, a.Identifier.Value)
			if a.Error != nil {
				testLogf(t, "test", "staging authz problem: type=%s detail=%s", a.Error.Type, a.Error.Detail)
			}
			for _, ch := range a.Challenges {
				if ch.Type != "dns-01" {
					continue
				}
				testLogf(t, "test", "staging dns-01 challenge detail: url=%s status=%s validated=%s", ch.URL, ch.Status, ch.Validated)
				if ch.Error != nil {
					testLogf(t, "test", "staging dns-01 challenge problem: type=%s detail=%s", ch.Error.Type, ch.Error.Detail)
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
	testLogf(t, "test", "staging certificate URL: %s", certURL)

	certs := parseCerts(t, client.fetchCert(t, certURL))
	assertCertSANs(t, certs, domain)
	testLogf(t, "test", "staging issued %d certificate(s)", len(certs))
}

// TestStagingLELegoViaGateway validates that an external ACME client (lego)
// can obtain a certificate through acme-gateway (which then routes upstream to
// Let's Encrypt staging).
func TestStagingLELegoViaGateway(t *testing.T) {
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

	// The gateway (configured by newStagingHarness from ACME_E2E_DNS_PRESENT_CMD/
	// _CLEANUP_CMD) owns dns-01 provisioning via its own dns_hook. lego, standing
	// in for the production client, performs no DNS work — see the no-op provider
	// below.
	h := newStagingHarness(t)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("lego key generation failed: %v", err)
	}

	legoUser := &legoE2EUser{Email: email, PrivateKey: privKey}
	legoConfig := legoapi.NewConfig(legoUser)
	legoConfig.CADirURL = h.GatewayURL + "/directory"
	legoConfig.Certificate.KeyType = legocrypto.EC256
	legoConfig.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec

	legoClient, err := legoapi.NewClient(legoConfig)
	if err != nil {
		t.Fatalf("lego client creation failed: %v", err)
	}
	// Model the production client exactly as certbot will run from now on:
	//   certbot --authenticator manual --preferred-challenges dns \
	//           --manual-auth-hook /bin/true --manual-cleanup-hook /bin/true
	// The client publishes no TXT and runs no DNS self-check; it answers the
	// challenge and lets the gateway publish the authoritative record and validate
	// upstream. WrapPreCheck short-circuits lego's built-in propagation wait (the
	// certbot manual plugin has no equivalent), and noopDNSProvider publishes
	// nothing — eliminating the dual-writer race where the client's own TXT could
	// be served to the CA by a lagging anycast node.
	skipDNSPreCheck := legodns01.WrapPreCheck(func(_, _, _ string, _ legodns01.PreCheckFunc) (bool, error) {
		return true, nil
	})
	if err := legoClient.Challenge.SetDNS01Provider(&noopDNSProvider{}, skipDNSPreCheck); err != nil {
		t.Fatalf("lego dns provider setup failed: %v", err)
	}

	reg, err := legoClient.Registration.Register(legoreg.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		t.Fatalf("lego registration failed: %v", err)
	}
	legoUser.Registration = reg

	obtainReq := legocert.ObtainRequest{Domains: []string{domain}, Bundle: true}
	certRes, err := legoClient.Certificate.Obtain(obtainReq)
	if err != nil {
		t.Fatalf("lego certificate obtain via gateway failed: %v", err)
	}
	if len(certRes.Certificate) == 0 {
		t.Fatal("lego returned empty certificate chain")
	}

	certs := parseCerts(t, certRes.Certificate)
	assertCertSANs(t, certs, domain)
	testLogf(t, "lego", "lego via gateway issued %d certificate(s)", len(certs))
}
