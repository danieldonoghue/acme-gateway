// Package upstream provides an ACME client for communicating with upstream CAs.
// It implements the JWS-signed requests required by RFC 8555 using the gateway's
// own keypair per upstream, handling nonce management and EAB.
package upstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// noncePoolSize is the number of upstream nonces cached in memory.
// A pool reduces HEAD /new-nonce round-trips when many goroutines make
// concurrent signed requests to the same upstream CA.
const noncePoolSize = 8

// Client is a signed-HTTP ACME client for a single upstream CA.
// It manages nonces, account keypairs, and JWS signing for all upstream requests.
type Client struct {
	directoryURL string
	httpClient   *http.Client

	mu         sync.Mutex
	key        *ecdsa.PrivateKey
	accountURL string // empty until account is registered
	directory  *ACMEDirectory

	// Nonce ring buffer. nonceCount is the number of cached nonces;
	// nonceHead is the next index to read, nonceTail the next to write.
	nonces     [noncePoolSize]string
	nonceHead  int
	nonceTail  int
	nonceCount int
}

// ACMEDirectory holds the URLs from the upstream /directory endpoint.
type ACMEDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// ACMEOrder is the upstream order object (RFC 8555 §7.1.3).
type ACMEOrder struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *ACMEError   `json:"error,omitempty"`
}

// ACMEAuthorization is the upstream authorization object (RFC 8555 §7.1.4).
type ACMEAuthorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Expires    string      `json:"expires,omitempty"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard,omitempty"`
}

// Challenge is a single ACME challenge within an authorization.
type Challenge struct {
	Type   string     `json:"type"`
	URL    string     `json:"url"`
	Token  string     `json:"token"`
	Status string     `json:"status"`
	Error  *ACMEError `json:"error,omitempty"`
}

// Identifier is an ACME identifier.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ACMEError represents an ACME problem document.
type ACMEError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e *ACMEError) Error() string {
	return fmt.Sprintf("ACME error %s: %s", e.Type, e.Detail)
}

// New creates a Client using the provided private key.
// key may be nil, in which case a new P-256 keypair is generated.
func New(directoryURL string, key *ecdsa.PrivateKey) (*Client, error) {
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating upstream key: %w", err)
		}
	}
	return &Client{
		directoryURL: directoryURL,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		key:          key,
	}, nil
}

// NewFromPEM creates a Client loading the private key from PEM bytes.
func NewFromPEM(directoryURL string, keyPEM []byte) (*Client, error) {
	key, err := parseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return New(directoryURL, key)
}

// SetAccountURL sets the upstream account URL (after registration).
func (c *Client) SetAccountURL(url string) {
	c.mu.Lock()
	c.accountURL = url
	c.mu.Unlock()
}

// AccountURL returns the upstream account URL.
func (c *Client) AccountURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accountURL
}

// KeyPEM returns the PEM-encoded private key.
func (c *Client) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// PublicJWK returns the public key as a JWK.
func (c *Client) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{Key: c.key.Public(), Algorithm: string(jose.ES256), Use: "sig"}
}

// Directory fetches (and caches) the upstream ACME directory.
func (c *Client) Directory(ctx context.Context) (*ACMEDirectory, error) {
	c.mu.Lock()
	if c.directory != nil {
		dir := c.directory
		c.mu.Unlock()
		return dir, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building directory request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck
		if len(body) > 256 {
			body = body[:256]
		}
		return nil, fmt.Errorf("upstream directory HTTP %d: %s", resp.StatusCode, body)
	}

	var dir ACMEDirectory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, fmt.Errorf("decoding directory: %w", err)
	}

	c.mu.Lock()
	c.directory = &dir
	c.mu.Unlock()
	return &dir, nil
}

// getNonce returns a cached nonce if one is available, otherwise fetches a
// fresh one from the upstream CA via HEAD /new-nonce.
func (c *Client) getNonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.nonceCount > 0 {
		n := c.nonces[c.nonceHead]
		c.nonces[c.nonceHead] = ""
		c.nonceHead = (c.nonceHead + 1) % noncePoolSize
		c.nonceCount--
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	dir, err := c.Directory(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching nonce: %w", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec

	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("upstream returned no Replay-Nonce")
	}
	return n, nil
}

// saveNonce adds a nonce from a response header to the pool for reuse.
// If the pool is full the nonce is dropped — the next caller will fetch a fresh one.
func (c *Client) saveNonce(n string) {
	if n == "" {
		return
	}
	c.mu.Lock()
	if c.nonceCount < noncePoolSize {
		c.nonces[c.nonceTail] = n
		c.nonceTail = (c.nonceTail + 1) % noncePoolSize
		c.nonceCount++
	}
	// Pool full: discard — caller will fetch fresh on next request.
	c.mu.Unlock()
}

// signedPost makes a JWS-signed POST to the upstream CA.
// payload == nil means POST-as-GET (empty string payload per RFC 8555).
func (c *Client) signedPost(ctx context.Context, url string, payload interface{}) (*http.Response, error) {
	nonce, err := c.getNonce(ctx)
	if err != nil {
		return nil, err
	}

	body, err := c.buildJWS(nonce, url, payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	c.saveNonce(resp.Header.Get("Replay-Nonce"))
	return resp, nil
}

// buildJWS serialises a JWS-signed request body.
func (c *Client) buildJWS(nonce, url string, payload interface{}) ([]byte, error) {
	sigKey := jose.SigningKey{Algorithm: jose.ES256, Key: c.key}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("nonce"), nonce)
	opts.WithHeader(jose.HeaderKey("url"), url)

	c.mu.Lock()
	acctURL := c.accountURL
	c.mu.Unlock()

	if acctURL != "" {
		opts.WithHeader(jose.HeaderKey("kid"), acctURL)
	} else {
		// New-account: embed the public JWK.
		jwk := jose.JSONWebKey{Key: c.key.Public(), Algorithm: string(jose.ES256), Use: "sig"}
		opts.WithHeader(jose.HeaderKey("jwk"), jwk)
	}

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		return nil, err
	}

	var jws *jose.JSONWebSignature
	if payload == nil {
		// POST-as-GET
		jws, err = signer.Sign([]byte(""))
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return nil, err2
		}
		jws, err = signer.Sign(payloadBytes)
	}
	if err != nil {
		return nil, err
	}

	return []byte(jws.FullSerialize()), nil
}

// parseACMEError reads an ACME problem document from a non-2xx response body.
func parseACMEError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body) //nolint:errcheck
	var ae ACMEError
	if err := json.Unmarshal(body, &ae); err != nil {
		return fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, string(body))
	}
	ae.Status = resp.StatusCode
	return &ae
}

// parseECPrivateKeyPEM parses a PEM-encoded EC private key.
func parseECPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing EC private key: %w", err)
	}
	return key, nil
}

// PublicKeyThumbprint returns the RFC 7638 SHA-256 thumbprint of the client's public key.
func (c *Client) PublicKeyThumbprint() (string, error) {
	jwk := jose.JSONWebKey{Key: c.key.Public()}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// KeyAuthorization computes the ACME key authorisation string for a challenge token.
// keyAuth = token + "." + base64url(SHA-256(accountKeyThumbprint))
func (c *Client) KeyAuthorization(token string) (string, error) {
	tp, err := c.PublicKeyThumbprint()
	if err != nil {
		return "", err
	}
	return token + "." + tp, nil
}
