// Command acme-probe reproduces the acme-gateway's exact upstream flow
// (directory → new-account+EAB → new-order → get-authz) directly against a CA,
// using the gateway's own internal/upstream client. It stops BEFORE deploying
// or triggering any challenge, so it safely isolates where the flow stalls.
//
// Throwaway diagnostic — delete when done.
//
//	go run ./cmd/acme-probe \
//	  -dir  https://one.nl.digicert.com/mpki/api/v1/acme/v2/directory \
//	  -kid  "$PRIVATE_CA_RSA_EAB_KID" \
//	  -hmac "$PRIVATE_CA_RSA_EAB_HMAC" \
//	  -domains sip-gw1-fi.aurorateleq.com,sip-gw-fi.aurorateleq.com
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

func main() {
	dir := flag.String("dir", "", "ACME directory URL (required)")
	kid := flag.String("kid", os.Getenv("PRIVATE_CA_RSA_EAB_KID"), "EAB key ID (defaults to $PRIVATE_CA_RSA_EAB_KID)")
	hmac := flag.String("hmac", os.Getenv("PRIVATE_CA_RSA_EAB_HMAC"), "EAB HMAC key (defaults to $PRIVATE_CA_RSA_EAB_HMAC)")
	email := flag.String("email", "driftinfo@aurorainnovation.com", "contact email")
	domainsCSV := flag.String("domains", "", "comma-separated dns identifiers (required)")
	profile := flag.String("profile", "", "upstream profile (empty = omit, matches private-ca-rsa)")
	doFinalize := flag.Bool("finalize", false, "actually finalize with a CSR and download the cert (ISSUES A REAL CERT)")
	csrKey := flag.String("csr-key", "rsa", "CSR key type when -finalize: rsa | ecdsa")
	flag.Parse()

	if *dir == "" || *domainsCSV == "" {
		fmt.Fprintln(os.Stderr, "error: -dir and -domains are required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Fresh account key each run — mirrors a per-gateway-account binding.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must("generate account key", err)

	client, err := upstream.New(*dir, key)
	must("create client", err)

	// ── directory + new-account (EAB) ────────────────────────────────────────
	var eab *config.EABConfig
	if *kid != "" || *hmac != "" {
		eab = &config.EABConfig{KeyID: *kid, HMACKey: *hmac}
	}
	step("Register (directory + new-account, EAB="+yesno(eab != nil)+")")
	acctURL, err := timed(func() (string, error) { return client.Register(ctx, *email, eab) })
	if err != nil {
		fail("Register", err)
	}
	fmt.Printf("    account_url = %s\n", acctURL)

	// ── new-order ────────────────────────────────────────────────────────────
	var ids []upstream.Identifier
	for _, d := range strings.Split(*domainsCSV, ",") {
		if d = strings.TrimSpace(d); d != "" {
			ids = append(ids, upstream.Identifier{Type: "dns", Value: d})
		}
	}
	step(fmt.Sprintf("SubmitOrder (%d identifiers, profile=%q)", len(ids), *profile))
	var orderURL string
	order, err := timedV(func() (*upstream.ACMEOrder, error) {
		o, u, e := client.SubmitOrder(ctx, ids, *profile)
		orderURL = u
		return o, e
	})
	if err != nil {
		fail("SubmitOrder", err)
	}
	fmt.Printf("    order_url = %s\n    status = %s  authorizations = %d\n", orderURL, order.Status, len(order.Authorizations))
	dump("order", order)

	// ── get-authz for each authorization (THE suspected stall point) ─────────
	for i, authzURL := range order.Authorizations {
		step(fmt.Sprintf("GetAuthorization [%d/%d] %s", i+1, len(order.Authorizations), authzURL))
		authz, err := timedV(func() (*upstream.ACMEAuthorization, error) {
			return client.GetAuthorization(ctx, authzURL)
		})
		if err != nil {
			fail(fmt.Sprintf("GetAuthorization[%d]", i), err)
		}
		fmt.Printf("    identifier = %s  status = %s\n", authz.Identifier.Value, authz.Status)
		for _, ch := range authz.Challenges {
			fmt.Printf("      challenge type=%s status=%s url=%s\n", ch.Type, ch.Status, ch.URL)
		}
		dump("authz", authz)
	}

	// ── re-poll the order (THE decisive test) ────────────────────────────────
	// All authorizations above are already valid. Per RFC 8555 §7.1.6 the order
	// must therefore transition pending → ready. Poll it and watch: if DigiCert
	// keeps it "pending", that is precisely what certbot and the gateway hang on.
	step("Re-poll order — expecting pending → ready now that all authz are valid")
	const polls = 6
	for i := 1; i <= polls; i++ {
		o, err := client.GetOrder(ctx, orderURL)
		if err != nil {
			fail("GetOrder(poll)", err)
		}
		fmt.Printf("    poll %d/%d: order status = %s\n", i, polls, o.Status)
		if o.Status == "ready" || o.Status == "valid" {
			fmt.Printf("\n✔ Order reached %q — DigiCert's order/authz path is HEALTHY.\n"+
				"  If production still hangs, the stall is in the gateway relaying this, not DigiCert.\n", o.Status)
			if *doFinalize {
				finalize(ctx, client, order.Finalize, orderURL, ids, *csrKey)
			} else {
				fmt.Println("  (re-run with -finalize -csr-key rsa|ecdsa to test CSR submission — the one step not yet exercised)")
			}
			return
		}
		if o.Status == "invalid" {
			dump("order", o)
			fail("order went invalid", fmt.Errorf("status=invalid"))
		}
		if i < polls {
			time.Sleep(5 * time.Second)
		}
	}

	fmt.Printf("\n✗ Order STUCK at pending across %d polls despite all authorizations being valid.\n"+
		"  This is a DigiCert-side order-state-machine problem (RFC 8555 §7.1.6 says it should be 'ready').\n"+
		"  certbot and the gateway both poll this order for 'ready' and will hang until timeout — exactly your symptom.\n", polls)
	os.Exit(1)
}

// finalize builds a CSR of the requested key type, submits it, polls the order
// to valid, and downloads the certificate — the exact step certbot performs
// that neither the logs nor the earlier phases have exercised. A key-type
// mismatch against DigiCert's product shows up here (badCSR, or a stuck order).
func finalize(ctx context.Context, client *upstream.Client, finalizeURL, orderURL string, ids []upstream.Identifier, csrKey string) {
	dnsNames := make([]string, 0, len(ids))
	for _, id := range ids {
		dnsNames = append(dnsNames, id.Value)
	}

	var signer crypto.Signer
	var err error
	switch strings.ToLower(csrKey) {
	case "ecdsa":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		fail("finalize", fmt.Errorf("-csr-key must be rsa or ecdsa, got %q", csrKey))
	}
	must("generate CSR key", err)

	step(fmt.Sprintf("Finalize with a %s CSR (SANs: %s)", strings.ToUpper(csrKey), strings.Join(dnsNames, ", ")))
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsNames[0]},
		DNSNames: dnsNames,
	}, signer)
	must("create CSR", err)

	o, err := timedV(func() (*upstream.ACMEOrder, error) {
		return client.FinalizeOrder(ctx, finalizeURL, csrDER)
	})
	if err != nil {
		fail("FinalizeOrder", err)
	}
	fmt.Printf("    order status after finalize = %s\n", o.Status)
	dump("order", o)

	step("Poll order → valid")
	const polls = 8
	for i := 1; i <= polls; i++ {
		o, err = client.GetOrder(ctx, orderURL)
		if err != nil {
			fail("GetOrder(finalize poll)", err)
		}
		fmt.Printf("    poll %d/%d: status = %s\n", i, polls, o.Status)
		switch o.Status {
		case "valid":
			fmt.Printf("\n✔ FULL FLOW SUCCEEDED with a %s CSR — certificate = %s\n"+
				"  So a %s CSR is accepted by this DigiCert product. If prod hangs, the client is sending a DIFFERENT key type.\n",
				strings.ToUpper(csrKey), o.Certificate, strings.ToUpper(csrKey))
			return
		case "invalid":
			dump("order", o)
			fail("order INVALID after finalize", fmt.Errorf("DigiCert rejected the %s CSR (see order.error above)", csrKey))
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Printf("\n✗ Order STUCK in %q after finalizing a %s CSR — DigiCert accepted finalize but never issued.\n"+
		"  This is the smoking gun for a wrong-key-type/product hang: the client would poll forever.\n", o.Status, strings.ToUpper(csrKey))
	os.Exit(1)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func step(s string) { fmt.Printf("\n▶ %s\n", s) }

func timed(f func() (string, error)) (string, error) {
	t := time.Now()
	v, err := f()
	fmt.Printf("    took %s\n", time.Since(t).Round(time.Millisecond))
	return v, err
}

func timedV[T any](f func() (T, error)) (T, error) {
	t := time.Now()
	v, err := f()
	fmt.Printf("    took %s\n", time.Since(t).Round(time.Millisecond))
	return v, err
}

func dump(label string, v any) {
	b, err := json.MarshalIndent(v, "    ", "  ")
	if err != nil {
		fmt.Printf("    %s = <marshal error: %v>\n", label, err)
		return
	}
	fmt.Printf("    %s = %s\n", label, string(b))
}

func must(what string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %s: %v\n", what, err)
		os.Exit(1)
	}
}

func fail(what string, err error) {
	fmt.Printf("\n✗ %s FAILED: %v\n", what, err)
	fmt.Println("→ This is the phase where production stalls. The error/latency above is DigiCert's response, isolated from certbot and the gateway.")
	os.Exit(1)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
