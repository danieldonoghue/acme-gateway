// Command acme-probe reproduces the acme-gateway's exact upstream flow
// (directory → new-account+EAB → new-order → get-authz) directly against an
// upstream ACME CA, using the gateway's own internal/upstream client. It stops
// BEFORE deploying or triggering any challenge, so it safely isolates where the
// flow stalls — useful for distinguishing a gateway bug from an upstream one.
//
// It touches no gateway state; each run registers a fresh throwaway account.
//
//	go run ./cmd/acme-probe \
//	  -dir     https://acme.example.com/directory \
//	  -kid     "$ACME_EAB_KID" \
//	  -hmac    "$ACME_EAB_HMAC" \
//	  -email   ops@example.com \
//	  -domains host1.example.com,host2.example.com
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
	kid := flag.String("kid", os.Getenv("ACME_EAB_KID"), "EAB key ID (defaults to $ACME_EAB_KID)")
	hmac := flag.String("hmac", os.Getenv("ACME_EAB_HMAC"), "EAB HMAC key (defaults to $ACME_EAB_HMAC)")
	email := flag.String("email", os.Getenv("ACME_EMAIL"), "account contact email (required; defaults to $ACME_EMAIL)")
	domainsCSV := flag.String("domains", "", "comma-separated dns identifiers (required)")
	profile := flag.String("profile", "", "upstream profile (empty = omit the field)")
	doFinalize := flag.Bool("finalize", false, "actually finalize with a CSR and download the cert (ISSUES A REAL CERT)")
	csrKey := flag.String("csr-key", "rsa", "CSR key type when -finalize: rsa | ecdsa")
	flag.Parse()

	if *dir == "" || *domainsCSV == "" || *email == "" {
		fmt.Fprintln(os.Stderr, "error: -dir, -domains and -email are required")
		flag.Usage()
		os.Exit(2)
	}
	// EAB requires both halves; one without the other fails later with a
	// low-signal base64/JWS error, so reject the mismatch upfront.
	if (*kid == "") != (*hmac == "") {
		fmt.Fprintln(os.Stderr, "error: -kid and -hmac must be provided together (EAB needs both, or neither)")
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
	// must therefore transition pending → ready. Poll it and watch: if the
	// upstream CA keeps it "pending", that is precisely what the client and the
	// gateway hang on.
	step("Re-poll order — expecting pending → ready now that all authz are valid")
	const polls = 6
	for i := 1; i <= polls; i++ {
		o, err := client.GetOrder(ctx, orderURL)
		if err != nil {
			fail("GetOrder(poll)", err)
		}
		fmt.Printf("    poll %d/%d: order status = %s\n", i, polls, o.Status)
		if o.Status == "ready" || o.Status == "valid" {
			fmt.Printf("\n✔ Order reached %q — the upstream CA's order/authz path is HEALTHY.\n"+
				"  If issuance still hangs, the stall is in the gateway relaying this, not the upstream CA.\n", o.Status)
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
		"  This is an upstream-CA-side order-state-machine problem (RFC 8555 §7.1.6 says it should be 'ready').\n"+
		"  ACME clients and the gateway both poll this order for 'ready' and will hang until timeout — exactly your symptom.\n", polls)
	os.Exit(1)
}

// finalize builds a CSR of the requested key type, submits it, polls the order
// to valid, and downloads the certificate — the exact step ACME clients perform
// that neither the logs nor the earlier phases have exercised. A key-type
// mismatch against the upstream CA's product shows up here (badCSR, or a stuck order).
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
				"  So a %s CSR is accepted by this upstream CA product. If issuance hangs, the client is sending a DIFFERENT key type.\n",
				strings.ToUpper(csrKey), o.Certificate, strings.ToUpper(csrKey))
			return
		case "invalid":
			dump("order", o)
			fail("order INVALID after finalize", fmt.Errorf("the upstream CA rejected the %s CSR (see order.error above)", csrKey))
		}
		time.Sleep(3 * time.Second)
	}
	fmt.Printf("\n✗ Order STUCK in %q after finalizing a %s CSR — the upstream CA accepted finalize but never issued.\n"+
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
	fmt.Println("→ This is the phase where issuance stalls. The error/latency above is the upstream CA's response, isolated from the client and the gateway.")
	os.Exit(1)
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
