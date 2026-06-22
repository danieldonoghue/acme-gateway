//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// acmeDirectory holds the URLs returned by the gateway's /directory endpoint.
type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// acmeOrder mirrors the RFC 8555 order object.
type acmeOrder struct {
	Status         string       `json:"status"`
	Identifiers    []acmeID     `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *acmeProblem `json:"error,omitempty"`
}

// acmeAuthz mirrors the RFC 8555 authorization object.
type acmeAuthz struct {
	Status     string      `json:"status"`
	Identifier acmeID      `json:"identifier"`
	Challenges []acmeChall `json:"challenges"`
}

// acmeChall mirrors a single challenge in an authorization.
type acmeChall struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// acmeID is an ACME identifier (type + value).
type acmeID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// acmeProblem is an RFC 7807 problem document as returned by ACME.
type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

type accountKeyAlgorithm string

const (
	accountKeyECDSA accountKeyAlgorithm = "ecdsa"
	accountKeyRSA   accountKeyAlgorithm = "rsa"
)

type csrKeyAlgorithm string

const (
	csrKeyECDSA csrKeyAlgorithm = "ecdsa"
	csrKeyRSA   csrKeyAlgorithm = "rsa"
)

// acmeClient implements a minimal ACME client for testing.
type acmeClient struct {
	dir    acmeDirectory
	key    interface{}
	alg    jose.SignatureAlgorithm
	jwkAlg string
	kidURL string // empty until account is registered
	hc     *http.Client
}

// newACMEClient creates an ACME client pointing at baseURL, trusting trustPool.
func newACMEClient(t *testing.T, baseURL string, trustPool *x509.CertPool) *acmeClient {
	t.Helper()
	return newACMEClientWithAccountKey(t, baseURL, trustPool, accountKeyECDSA)
}

// newACMEClientWithAccountKey creates an ACME client with a selectable
// account key algorithm (ECDSA or RSA) for JWS signing.
func newACMEClientWithAccountKey(t *testing.T, baseURL string, trustPool *x509.CertPool, keyAlg accountKeyAlgorithm) *acmeClient {
	t.Helper()

	var (
		key interface{}
		alg jose.SignatureAlgorithm
		jwk string
		err error
	)

	switch keyAlg {
	case accountKeyECDSA:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		alg = jose.ES256
		jwk = string(jose.ES256)
	case accountKeyRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		alg = jose.RS256
		jwk = string(jose.RS256)
	default:
		t.Fatalf("unsupported account key algorithm %q", keyAlg)
	}
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}

	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: trustPool},
		},
		Timeout: 30 * time.Second,
	}

	c := &acmeClient{key: key, alg: alg, jwkAlg: jwk, hc: hc}
	c.fetchDirectory(t, baseURL)
	return c
}

func (c *acmeClient) fetchDirectory(t *testing.T, baseURL string) {
	t.Helper()
	resp, err := c.hc.Get(baseURL + "/directory")
	if err != nil {
		t.Fatalf("GET /directory: %v", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&c.dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
}

// freshNonce fetches a fresh replay nonce via HEAD newNonce.
func (c *acmeClient) freshNonce(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodHead, c.dir.NewNonce, http.NoBody)
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("HEAD newNonce: %v", err)
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatal("empty Replay-Nonce from HEAD newNonce")
	}
	return nonce
}

// post signs payload with the ACME key and POSTs it to url.
// A nil payload produces a POST-as-GET request (empty body, per RFC 8555 §6.3).
func (c *acmeClient) post(t *testing.T, url string, payload interface{}) *http.Response {
	t.Helper()
	body := c.sign(t, url, payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// sign builds a JWS-signed request body.
// payload == nil → POST-as-GET (empty string payload per RFC 8555 §6.3).
func (c *acmeClient) sign(t *testing.T, url string, payload interface{}) []byte {
	t.Helper()
	nonce := c.freshNonce(t)

	sigKey := jose.SigningKey{Algorithm: c.alg, Key: c.key}
	opts := new(jose.SignerOptions).
		WithHeader("nonce", nonce).
		WithHeader("url", url)

	if c.kidURL != "" {
		opts = opts.WithHeader("kid", c.kidURL)
	} else {
		pubKey, err := accountPublicKey(c.key)
		if err != nil {
			t.Fatalf("account public key: %v", err)
		}
		jwk := jose.JSONWebKey{
			Key:       pubKey,
			Algorithm: c.jwkAlg,
			Use:       "sig",
		}
		opts = opts.WithHeader("jwk", jwk)
	}

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var jws *jose.JSONWebSignature
	if payload == nil {
		// POST-as-GET: empty payload (base64url of 0 bytes == "")
		jws, err = signer.Sign([]byte{})
	} else {
		body, merr := json.Marshal(payload)
		if merr != nil {
			t.Fatalf("marshal payload: %v", merr)
		}
		jws, err = signer.Sign(body)
	}
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return []byte(jws.FullSerialize())
}

// register creates a new ACME account and stores the account URL.
func (c *acmeClient) register(t *testing.T) string {
	t.Helper()
	resp := c.post(t, c.dir.NewAccount, map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:test@example.invalid"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("newAccount: unexpected status %d: %s", resp.StatusCode, body)
	}

	c.kidURL = resp.Header.Get("Location")
	if c.kidURL == "" {
		t.Fatal("newAccount: no Location header (expected account URL)")
	}
	return c.kidURL
}

// newOrder creates a new ACME order for domain.
func (c *acmeClient) newOrder(t *testing.T, domain string) (acmeOrder, string) {
	t.Helper()
	return c.newOrderWithProfile(t, domain, "")
}

// newOrderWithProfile creates a new ACME order and optionally sets an ACME
// profile value in the newOrder payload.
func (c *acmeClient) newOrderWithProfile(t *testing.T, domain, profile string) (acmeOrder, string) {
	t.Helper()
	payload := map[string]interface{}{
		"identifiers": []acmeID{{Type: "dns", Value: domain}},
	}
	if profile != "" {
		payload["profile"] = profile
	}

	resp := c.post(t, c.dir.NewOrder, payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("newOrder: unexpected status %d: %s", resp.StatusCode, body)
	}

	var order acmeOrder
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		t.Fatalf("decode order: %v", err)
	}
	orderURL := resp.Header.Get("Location")
	if orderURL == "" {
		t.Fatal("newOrder: no Location header")
	}
	return order, orderURL
}

// getAuthz fetches an authorization object.
func (c *acmeClient) getAuthz(t *testing.T, authzURL string) acmeAuthz {
	t.Helper()
	resp := c.post(t, authzURL, nil) // POST-as-GET
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("getAuthz: unexpected status %d: %s", resp.StatusCode, body)
	}

	var authz acmeAuthz
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		t.Fatalf("decode authz: %v", err)
	}
	return authz
}

// triggerChallenge responds to a challenge, signalling to the CA that it should
// validate. For Pebble with PEBBLE_VA_ALWAYS_VALID=1 this always succeeds.
func (c *acmeClient) triggerChallenge(t *testing.T, challURL string) {
	t.Helper()
	resp := c.post(t, challURL, map[string]interface{}{}) // empty JSON object per RFC 8555 §7.5.1
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("triggerChallenge: unexpected status %d: %s", resp.StatusCode, body)
	}

	linkValues := resp.Header.Values("Link")
	if !hasLinkRelation(linkValues, "index") {
		t.Fatalf("triggerChallenge: missing Link rel=\"index\" header: %v", linkValues)
	}
	if !hasLinkRelation(linkValues, "up") {
		t.Fatalf("triggerChallenge: missing Link rel=\"up\" header: %v", linkValues)
	}
}

func hasLinkRelation(linkValues []string, rel string) bool {
	needle := `rel="` + rel + `"`
	for _, v := range linkValues {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

// pollOrder polls an order URL until its status is no longer "pending" or
// "processing", or until the timeout elapses.
func (c *acmeClient) pollOrder(t *testing.T, orderURL string) acmeOrder {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp := c.post(t, orderURL, nil) // POST-as-GET
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pollOrder: unexpected status %d: %s", resp.StatusCode, body)
		}
		var order acmeOrder
		if err := json.Unmarshal(body, &order); err != nil {
			t.Fatalf("decode order: %v", err)
		}

		if order.Status != "pending" && order.Status != "processing" {
			return order
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("pollOrder: timed out waiting for order to leave pending/processing")
	return acmeOrder{}
}

// finalize generates a CSR for domain, POSTs it to finalizeURL, and polls the
// order until a certificate URL is available. Returns the certificate URL.
func (c *acmeClient) finalize(t *testing.T, finalizeURL, orderURL, domain string) string {
	t.Helper()
	return c.finalizeWithCSRKey(t, finalizeURL, orderURL, domain, csrKeyECDSA)
}

// finalizeWithCSRKey finalizes an order using a CSR created with the selected
// key algorithm.
func (c *acmeClient) finalizeWithCSRKey(t *testing.T, finalizeURL, orderURL, domain string, keyAlg csrKeyAlgorithm) string {
	t.Helper()

	csrDER, err := createCSRDER(t, domain, keyAlg)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	// RFC 8555 §7.4: csr field is the base64url-encoded DER, without PEM wrapping
	// or padding. json.Marshal encodes []byte as standard base64, so we must
	// pre-encode as a string using RawURLEncoding.
	resp := c.post(t, finalizeURL, map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("finalize: unexpected status %d: %s", resp.StatusCode, body)
	}

	// Poll until the order transitions to "valid" and has a certificate URL.
	order := c.pollOrder(t, orderURL)
	if order.Status != "valid" {
		if order.Error != nil {
			t.Fatalf("order failed: %s – %s", order.Error.Type, order.Error.Detail)
		}
		t.Fatalf("order in unexpected state %q after finalize", order.Status)
	}
	if order.Certificate == "" {
		t.Fatal("order valid but no certificate URL")
	}
	return order.Certificate
}

func createCSRDER(t *testing.T, domain string, keyAlg csrKeyAlgorithm) ([]byte, error) {
	t.Helper()

	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}

	switch keyAlg {
	case csrKeyECDSA:
		csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ECDSA CSR key: %w", err)
		}
		return x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
	case csrKeyRSA:
		csrKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA CSR key: %w", err)
		}
		return x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
	default:
		return nil, fmt.Errorf("unsupported CSR key algorithm %q", keyAlg)
	}
}

func accountPublicKey(key interface{}) (interface{}, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case *rsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported account key type %T", key)
	}
}

// fetchCert retrieves the certificate chain at certURL using POST-as-GET.
func (c *acmeClient) fetchCert(t *testing.T, certURL string) []byte {
	t.Helper()
	resp := c.post(t, certURL, nil) // POST-as-GET
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("fetchCert: unexpected status %d: %s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("fetchCert read: %v", err)
	}
	return body
}

// parseCerts parses all PEM certificates from certBytes and returns them.
func parseCerts(t *testing.T, certBytes []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := certBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse cert: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatal("parseCerts: no certificates found")
	}
	return certs
}

// assertCertSANs fails the test if the leaf certificate does not contain the
// expected DNS SAN.
func assertCertSANs(t *testing.T, certs []*x509.Certificate, want string) {
	t.Helper()
	leaf := certs[0]
	for _, san := range leaf.DNSNames {
		if san == want {
			return
		}
	}
	t.Fatalf("leaf cert has SANs %v, want %q", leaf.DNSNames, want)
}

func mustString(v interface{}) string {
	return fmt.Sprintf("%v", v)
}
