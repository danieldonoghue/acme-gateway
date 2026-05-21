package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// buildTestJWS creates a valid ACME-style JWS for testing.
// If kid is non-empty the JWS uses kid; otherwise embeds the JWK.
func buildTestJWS(t *testing.T, key *ecdsa.PrivateKey, payload []byte, nonce, url, kid string) []byte {
	t.Helper()

	sigKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("nonce"), nonce)
	opts.WithHeader(jose.HeaderKey("url"), url)

	if kid != "" {
		opts.WithHeader(jose.HeaderKey("kid"), kid)
	} else {
		jwk := jose.JSONWebKey{Key: key.Public(), Algorithm: string(jose.ES256), Use: "sig"}
		opts.WithHeader(jose.HeaderKey("jwk"), jwk)
	}

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	var jws *jose.JSONWebSignature
	if len(payload) == 0 {
		jws, err = signer.Sign([]byte{})
	} else {
		jws, err = signer.Sign(payload)
	}
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	raw := []byte(jws.FullSerialize())
	return raw
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestParseJWS_NewAccount(t *testing.T) {
	key := newTestKey(t)
	payload := []byte(`{"contact":["mailto:test@example.com"]}`)
	body := buildTestJWS(t, key, payload, "test-nonce-1", "https://gw/new-account", "")

	parsed, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.EmbeddedJWK == nil {
		t.Fatal("expected embedded JWK for new-account")
	}
	if parsed.AccountKID != "" {
		t.Errorf("expected empty AccountKID, got %q", parsed.AccountKID)
	}
	if parsed.Nonce != "test-nonce-1" {
		t.Errorf("nonce = %q, want %q", parsed.Nonce, "test-nonce-1")
	}
	if parsed.URL != "https://gw/new-account" {
		t.Errorf("url = %q, want %q", parsed.URL, "https://gw/new-account")
	}
	if string(parsed.Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", parsed.Payload, payload)
	}
}

func TestParseJWS_ExistingAccount(t *testing.T) {
	key := newTestKey(t)
	payload := []byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`)
	body := buildTestJWS(t, key, payload, "nonce-2", "https://gw/new-order", "https://gw/account/abc123")

	parsed, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.EmbeddedJWK != nil {
		t.Fatal("expected no embedded JWK for existing account")
	}
	if parsed.AccountKID != "https://gw/account/abc123" {
		t.Errorf("AccountKID = %q, want %q", parsed.AccountKID, "https://gw/account/abc123")
	}
}

func TestParseJWS_PostAsGet(t *testing.T) {
	key := newTestKey(t)
	// POST-as-GET: empty payload
	body := buildTestJWS(t, key, nil, "nonce-pag", "https://gw/order/xyz", "https://gw/account/abc")

	parsed, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parsed.Payload) != 0 {
		t.Errorf("expected empty payload for POST-as-GET, got %q", parsed.Payload)
	}
}

func TestParseJWS_MissingNonce(t *testing.T) {
	key := newTestKey(t)
	// Build a JWS manually without the nonce header.
	sigKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("url"), "https://gw/new-account")
	jwk := jose.JSONWebKey{Key: key.Public()}
	opts.WithHeader(jose.HeaderKey("jwk"), jwk)

	signer, _ := jose.NewSigner(sigKey, opts)
	jws, _ := signer.Sign([]byte("{}"))
	raw := []byte(jws.FullSerialize())

	_, err := ParseJWS(raw)
	if err == nil {
		t.Fatal("expected error for missing nonce")
	}
}

func TestParseJWS_MissingURL(t *testing.T) {
	key := newTestKey(t)
	sigKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("nonce"), "some-nonce")
	jwk := jose.JSONWebKey{Key: key.Public()}
	opts.WithHeader(jose.HeaderKey("jwk"), jwk)

	signer, _ := jose.NewSigner(sigKey, opts)
	jws, _ := signer.Sign([]byte("{}"))
	raw := []byte(jws.FullSerialize())

	_, err := ParseJWS(raw)
	if err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestVerifySignature_Valid(t *testing.T) {
	key := newTestKey(t)
	payload := []byte(`{"test":true}`)
	body := buildTestJWS(t, key, payload, "nonce", "https://gw/new-account", "")

	parsed, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if err := parsed.VerifySignature(key.Public()); err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	key1 := newTestKey(t)
	key2 := newTestKey(t)
	body := buildTestJWS(t, key1, []byte("{}"), "nonce", "https://gw/new-account", "")

	parsed, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if err := parsed.VerifySignature(key2.Public()); err == nil {
		t.Error("expected signature verification to fail with wrong key")
	}
}

func TestJWKThumbprint_Deterministic(t *testing.T) {
	key := newTestKey(t)
	jwk := &jose.JSONWebKey{Key: key.Public()}

	tp1, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	tp2, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if tp1 != tp2 {
		t.Errorf("thumbprint is not deterministic: %q vs %q", tp1, tp2)
	}
	if tp1 == "" {
		t.Error("thumbprint is empty")
	}
}

func TestKeyTypeFromJWK(t *testing.T) {
	ecKey := newTestKey(t)
	ecJWK := &jose.JSONWebKey{Key: ecKey.Public()}
	kt, err := KeyTypeFromJWK(ecJWK)
	if err != nil {
		t.Fatal(err)
	}
	if kt != "ECDSA" {
		t.Errorf("expected ECDSA, got %q", kt)
	}
}
