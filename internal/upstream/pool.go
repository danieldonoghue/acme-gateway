package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
	"github.com/danieldonoghue/acme-gateway/internal/store"
)

// Pool manages one Client per configured upstream CA, lazily initialising
// accounts and caching clients in memory.
type Pool struct {
	cfg   *config.Config
	store *store.Store

	mu      sync.Mutex
	clients map[string]*Client
}

// NewPool creates a Pool from the application config.
func NewPool(cfg *config.Config, st *store.Store) *Pool {
	return &Pool{
		cfg:     cfg,
		store:   st,
		clients: make(map[string]*Client),
	}
}

// Get returns the Client for the given upstream ID.
// If an account keypair exists in the store it is loaded; otherwise a new key is generated
// but NOT yet registered (call EnsureAccount to register).
func (p *Pool) Get(upstreamID string) (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.getOrCreate(upstreamID)
}

// EnsureAccount ensures the gateway has a registered account at upstreamID,
// creating and persisting one (with EAB if configured) if needed.
// It is safe to call concurrently; the first caller registers and subsequent
// callers reuse the result.
func (p *Pool) EnsureAccount(ctx context.Context, upstreamID string) (*Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, err := p.getOrCreate(upstreamID)
	if err != nil {
		return nil, err
	}

	if client.AccountURL() != "" {
		return client, nil // already registered
	}

	upCfg := p.cfg.Upstreams[upstreamID]

	// Register with the upstream CA.
	accountURL, err := client.Register(ctx, upCfg.ContactEmail, upCfg.EAB)
	if err != nil {
		return nil, fmt.Errorf("registering with %q: %w", upstreamID, err)
	}

	// Persist the keypair and account URL.
	keyPEM, err := client.KeyPEM()
	if err != nil {
		return nil, err
	}
	ua := &model.UpstreamAccount{
		UpstreamID: upstreamID,
		AccountURL: accountURL,
		PrivateKey: string(keyPEM),
		CreatedAt:  time.Now().UTC(),
	}
	if err := p.store.SaveUpstreamAccount(ua); err != nil {
		return nil, fmt.Errorf("persisting upstream account: %w", err)
	}
	return client, nil
}

// getOrCreate is the internal (already-locked) get-or-create for a client.
func (p *Pool) getOrCreate(upstreamID string) (*Client, error) {
	if c, ok := p.clients[upstreamID]; ok {
		return c, nil
	}

	upCfg, ok := p.cfg.Upstreams[upstreamID]
	if !ok {
		return nil, fmt.Errorf("upstream %q not in config", upstreamID)
	}

	// Load existing keypair from the store, or generate a fresh one.
	ua, err := p.store.GetUpstreamAccount(upstreamID)
	if err != nil {
		return nil, fmt.Errorf("loading upstream account: %w", err)
	}

	var key *ecdsa.PrivateKey
	if ua != nil {
		key, err = parseECPrivateKeyPEM([]byte(ua.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("parsing upstream key for %q: %w", upstreamID, err)
		}
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating upstream key: %w", err)
		}
	}

	client, err := New(upCfg.DirectoryURL, key)
	if err != nil {
		return nil, err
	}

	if ua != nil {
		client.SetAccountURL(ua.AccountURL)
	}

	p.clients[upstreamID] = client
	return client, nil
}

// GenerateKeyPEM generates a fresh P-256 private key and returns the PEM encoding.
func GenerateKeyPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
