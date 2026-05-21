package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── constructors ──────────────────────────────────────────────────────────────

func TestNew_NilKeyGeneratesOne(t *testing.T) {
	c, err := New("https://acme.example.com/directory", nil)
	if err != nil {
		t.Fatalf("New with nil key: %v", err)
	}
	if c.key == nil {
		t.Fatal("expected a key to be generated")
	}
}

func TestNew_UsesProvidedKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, err := New("https://acme.example.com/directory", key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.key != key {
		t.Fatal("expected the provided key to be stored")
	}
}

func TestNewFromPEM_RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	c, err := NewFromPEM("https://acme.example.com/directory", pemBytes)
	if err != nil {
		t.Fatalf("NewFromPEM: %v", err)
	}
	if !c.key.Equal(key) {
		t.Fatal("key mismatch after PEM round-trip")
	}
}

func TestNewFromPEM_NoPEMBlock(t *testing.T) {
	_, err := NewFromPEM("https://acme.example.com/directory", []byte("not pem data"))
	if err == nil {
		t.Fatal("expected error for input with no PEM block")
	}
}

func TestNewFromPEM_InvalidDER(t *testing.T) {
	bad := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})
	_, err := NewFromPEM("https://acme.example.com/directory", bad)
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestNewWithHTTPClient_Stores(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	custom := &http.Client{}
	c, err := NewWithHTTPClient("https://acme.example.com/directory", key, custom)
	if err != nil {
		t.Fatalf("NewWithHTTPClient: %v", err)
	}
	if c.httpClient != custom {
		t.Fatal("expected custom http.Client to be stored")
	}
}

func TestNewWithHTTPClient_NilFallback(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, err := NewWithHTTPClient("https://acme.example.com/directory", key, nil)
	if err != nil {
		t.Fatalf("NewWithHTTPClient: %v", err)
	}
	if c.httpClient == nil {
		t.Fatal("expected default http.Client when nil is passed")
	}
}

// ── HTTPClientWithCACert ──────────────────────────────────────────────────────

func TestHTTPClientWithCACert_Valid(t *testing.T) {
	pemBytes := selfSignedPEM(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}

	hc, err := HTTPClientWithCACert(path)
	if err != nil {
		t.Fatalf("HTTPClientWithCACert: %v", err)
	}
	if hc == nil {
		t.Fatal("expected non-nil http.Client")
	}
}

func TestHTTPClientWithCACert_FileNotFound(t *testing.T) {
	_, err := HTTPClientWithCACert(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHTTPClientWithCACert_NoCerts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(path, []byte("no certificate here\n"), 0600) //nolint:errcheck
	_, err := HTTPClientWithCACert(path)
	if err == nil {
		t.Fatal("expected error for PEM file containing no valid certificates")
	}
}

// ── key accessors ─────────────────────────────────────────────────────────────

func TestKeyPEM_RoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)

	pemBytes, err := c.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}

	parsed, err := parseECPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("parseECPrivateKeyPEM: %v", err)
	}
	if !parsed.Equal(key) {
		t.Fatal("key mismatch after KeyPEM round-trip")
	}
}

func TestPublicJWK_Fields(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)

	jwk := c.PublicJWK()
	if jwk.Algorithm != "ES256" {
		t.Errorf("Algorithm = %q, want ES256", jwk.Algorithm)
	}
	if jwk.Use != "sig" {
		t.Errorf("Use = %q, want sig", jwk.Use)
	}
	if jwk.Key == nil {
		t.Fatal("expected non-nil public key in JWK")
	}
}

func TestPublicKeyThumbprint_Stable(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)

	tp1, err := c.PublicKeyThumbprint()
	if err != nil {
		t.Fatalf("PublicKeyThumbprint: %v", err)
	}
	tp2, _ := c.PublicKeyThumbprint()
	if tp1 != tp2 {
		t.Fatal("thumbprint not stable across calls")
	}
	if tp1 == "" {
		t.Fatal("expected non-empty thumbprint")
	}
}

func TestKeyAuthorization_Format(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)

	ka, err := c.KeyAuthorization("my-token")
	if err != nil {
		t.Fatalf("KeyAuthorization: %v", err)
	}
	// Must be "token.thumbprint"
	parts := strings.SplitN(ka, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("expected exactly one dot in %q", ka)
	}
	if parts[0] != "my-token" {
		t.Errorf("token part = %q, want my-token", parts[0])
	}
	if parts[1] == "" {
		t.Error("thumbprint part must not be empty")
	}
}

// ── account URL ───────────────────────────────────────────────────────────────

func TestSetGetAccountURL(t *testing.T) {
	c, _ := New("https://acme.example.com/directory", nil)
	if c.AccountURL() != "" {
		t.Fatal("expected empty account URL initially")
	}
	const want = "https://acme.example.com/acct/123"
	c.SetAccountURL(want)
	if got := c.AccountURL(); got != want {
		t.Errorf("AccountURL = %q, want %q", got, want)
	}
}

// ── ACMEError ─────────────────────────────────────────────────────────────────

func TestACMEError_Error(t *testing.T) {
	e := &ACMEError{
		Type:   "urn:ietf:params:acme:error:malformed",
		Detail: "bad nonce",
		Status: 400,
	}
	msg := e.Error()
	if !strings.Contains(msg, "malformed") {
		t.Errorf("Error() = %q; expected it to contain the type", msg)
	}
	if !strings.Contains(msg, "bad nonce") {
		t.Errorf("Error() = %q; expected it to contain the detail", msg)
	}
}

// ── buildJWS ──────────────────────────────────────────────────────────────────

func TestBuildJWS_NoAccount_EmbedsJWK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)

	body, err := c.buildJWS("test-nonce", "https://acme.example.com/new-account",
		map[string]bool{"termsOfServiceAgreed": true})
	if err != nil {
		t.Fatalf("buildJWS: %v", err)
	}

	hdr := decodeProtectedHeader(t, body)
	if _, ok := hdr["jwk"]; !ok {
		t.Fatal("expected 'jwk' header when no account URL is set")
	}
	if _, ok := hdr["kid"]; ok {
		t.Fatal("expected no 'kid' header when no account URL is set")
	}
}

func TestBuildJWS_WithAccount_UsesKID(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)
	c.SetAccountURL("https://acme.example.com/acct/99")

	body, err := c.buildJWS("nonce", "https://acme.example.com/order", map[string]string{})
	if err != nil {
		t.Fatalf("buildJWS: %v", err)
	}

	hdr := decodeProtectedHeader(t, body)
	if _, ok := hdr["kid"]; !ok {
		t.Fatal("expected 'kid' header when account URL is set")
	}
	if _, ok := hdr["jwk"]; ok {
		t.Fatal("expected no 'jwk' header when account URL is set")
	}
}

func TestBuildJWS_PostAsGET_NilPayload(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c, _ := New("https://acme.example.com/directory", key)
	c.SetAccountURL("https://acme.example.com/acct/1")

	body, err := c.buildJWS("nonce", "https://acme.example.com/cert/x", nil)
	if err != nil {
		t.Fatalf("buildJWS nil payload: %v", err)
	}
	// The payload field in the flat JWS must be the empty string (base64url("") == "").
	var flat struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &flat); err != nil {
		t.Fatalf("unmarshal JWS: %v", err)
	}
	if flat.Payload != "" {
		t.Errorf("POST-as-GET payload = %q, want empty string", flat.Payload)
	}
}

// ── nonce pool ────────────────────────────────────────────────────────────────

func TestSaveNonce_PoolFull_DropsExtra(t *testing.T) {
	c, _ := New("https://acme.example.com/directory", nil)

	// Fill pool to capacity then add one more — the extra must be silently dropped.
	for i := 0; i <= noncePoolSize; i++ {
		c.saveNonce(fmt.Sprintf("nonce-%d", i))
	}

	c.mu.Lock()
	count := c.nonceCount
	c.mu.Unlock()

	if count != noncePoolSize {
		t.Errorf("pool has %d nonces after overflow, want %d", count, noncePoolSize)
	}
}

func TestSaveNonce_EmptyStringIgnored(t *testing.T) {
	c, _ := New("https://acme.example.com/directory", nil)
	c.saveNonce("")
	c.mu.Lock()
	count := c.nonceCount
	c.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 nonces after saving empty string, got %d", count)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// selfSignedPEM generates a minimal self-signed certificate PEM for use in tests.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ── parseACMEError ───────────────────────────────────────────────────────────

func TestParseACMEError_ValidJSON(t *testing.T) {
	body := `{"type":"urn:ietf:params:acme:error:badNonce","detail":"nonce is invalid"}`
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	err := parseACMEError(resp)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	ae, ok := err.(*ACMEError)
	if !ok {
		t.Fatalf("expected *ACMEError, got %T", err)
	}
	if ae.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", ae.Status, http.StatusBadRequest)
	}
	if ae.Type != "urn:ietf:params:acme:error:badNonce" {
		t.Errorf("Type = %q", ae.Type)
	}
	if ae.Detail != "nonce is invalid" {
		t.Errorf("Detail = %q", ae.Detail)
	}
}

func TestParseACMEError_InvalidJSON(t *testing.T) {
	body := `not-json`
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	err := parseACMEError(resp)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	// Falls back to plain string error, not *ACMEError.
	if _, ok := err.(*ACMEError); ok {
		t.Fatal("expected plain error for invalid JSON body, not *ACMEError")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

// decodeProtectedHeader parses the base64url-encoded JOSE protected header from
// a flat JWS serialisation.
func decodeProtectedHeader(t *testing.T, jwsBody []byte) map[string]json.RawMessage {
	t.Helper()
	var flat struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(jwsBody, &flat); err != nil {
		t.Fatalf("unmarshal JWS body: %v", err)
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(flat.Protected)
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal protected header: %v", err)
	}
	return hdr
}
