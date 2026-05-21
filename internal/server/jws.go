// Package server implements the ACMEv2 gateway HTTP server.
package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// allowedAlgorithms lists the JWS algorithms the gateway accepts from clients.
var allowedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
}

// rawJWS is used to extract the payload before go-jose parses it,
// since go-jose does not expose a public payload accessor on ParsedJWS.
type rawJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ParsedJWS is the validated structural result of an inbound ACME JWS.
// Signature verification is intentionally deferred until the caller has
// retrieved the account public key (which requires the account store).
type ParsedJWS struct {
	// Payload is the decoded payload bytes. Empty slice for POST-as-GET.
	Payload []byte

	// EmbeddedJWK is non-nil for new-account requests that embed the public key.
	EmbeddedJWK *jose.JSONWebKey

	// AccountKID is non-empty for requests that reference an existing account URL.
	AccountKID string

	// Nonce extracted from the protected header (must be consumed by the caller).
	Nonce string

	// URL extracted from the protected header.
	URL string

	// raw preserves the parsed JWS for deferred signature verification.
	raw *jose.JSONWebSignature
}

// ParseJWS parses the raw body of an ACME POST request and performs all
// structural checks defined in RFC 8555 §6.2, except nonce consumption and
// signature verification (both are the caller's responsibility).
//
// Specifically it checks:
//   - Exactly one JWS signature using an allowed algorithm
//   - Protected header contains alg, nonce, and url fields
//   - Protected header has exactly one of jwk or kid (not both)
func ParseJWS(body []byte) (*ParsedJWS, error) {
	// Extract the payload directly from the raw JSON before go-jose parses it,
	// since go-jose's payload field is not publicly accessible on a parsed JWS.
	var raw rawJWS
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("malformed JWS: %w", err)
	}

	jws, err := jose.ParseSigned(string(body), allowedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("malformed JWS: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("JWS must have exactly one signature")
	}

	headers := jws.Signatures[0].Protected

	// "nonce" is a recognised JOSE header; go-jose promotes it to headers.Nonce.
	nonce := headers.Nonce
	if nonce == "" {
		return nil, errors.New("missing nonce in JWS protected header")
	}
	// "url" is not a standard JOSE header; it lives in ExtraHeaders.
	url, _ := headers.ExtraHeaders[jose.HeaderKey("url")].(string)
	if url == "" {
		return nil, errors.New("missing url in JWS protected header")
	}

	hasJWK := headers.JSONWebKey != nil
	hasKID := headers.KeyID != ""
	if hasJWK && hasKID {
		return nil, errors.New("JWS must not have both jwk and kid in protected header")
	}
	if !hasJWK && !hasKID {
		return nil, errors.New("JWS must have either jwk or kid in protected header")
	}

	result := &ParsedJWS{
		Nonce: nonce,
		URL:   url,
		raw:   jws,
	}

	if hasJWK {
		result.EmbeddedJWK = headers.JSONWebKey
	} else {
		result.AccountKID = headers.KeyID
	}

	// Decode payload; an empty string is valid (POST-as-GET per RFC 8555 §6.3).
	if raw.Payload != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(raw.Payload)
		if err != nil {
			return nil, fmt.Errorf("decoding JWS payload: %w", err)
		}
		result.Payload = decoded
	}

	return result, nil
}

// VerifySignature verifies the JWS signature against the given public key.
// Must be called after ParseJWS once the key has been retrieved from the store.
func (p *ParsedJWS) VerifySignature(pubKey crypto.PublicKey) error {
	_, err := p.raw.Verify(pubKey)
	if err != nil {
		return fmt.Errorf("invalid JWS signature: %w", err)
	}
	return nil
}

// JWKThumbprint computes the RFC 7638 SHA-256 thumbprint of a JWK and returns
// it as a base64url-encoded string. This is used as the account ID.
func JWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// KeyTypeFromJWK returns "RSA" or "ECDSA" based on the JWK's key type.
func KeyTypeFromJWK(jwk *jose.JSONWebKey) (string, error) {
	switch jwk.Key.(type) {
	case *rsa.PublicKey, *rsa.PrivateKey:
		return "RSA", nil
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		return "ECDSA", nil
	default:
		return "", fmt.Errorf("unsupported key type %T", jwk.Key)
	}
}
