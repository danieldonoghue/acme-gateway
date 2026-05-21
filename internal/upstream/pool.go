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

// Pool manages a slice of Clients per configured upstream CA, lazily initialising
// accounts and caching clients in memory. Multiple accounts per upstream let the
// gateway spread new-order load across LE's per-account rate limits.
type Pool struct {
	cfg   *config.Config
	store *store.Store

	mu       sync.Mutex
	clients  map[string][]*Client // keyed by upstream ID, indexed by slot
	nextSlot map[string]int       // round-robin counter per upstream

	// regMu serialises the regMap itself; individual entries are per (upstream, slot).
	regMu  sync.Mutex
	regMap map[string]*sync.Mutex // key: "upstreamID:slot"
}

// NewPool creates a Pool from the application config.
func NewPool(cfg *config.Config, st *store.Store) *Pool {
	return &Pool{
		cfg:      cfg,
		store:    st,
		clients:  make(map[string][]*Client),
		nextSlot: make(map[string]int),
		regMap:   make(map[string]*sync.Mutex),
	}
}

// slotRegLock returns the per-(upstream, slot) mutex used to serialise account
// registration. Different slots for the same upstream can register concurrently.
func (p *Pool) slotRegLock(upstreamID string, slot int) *sync.Mutex {
	key := fmt.Sprintf("%s:%d", upstreamID, slot)
	p.regMu.Lock()
	defer p.regMu.Unlock()
	if _, ok := p.regMap[key]; !ok {
		p.regMap[key] = &sync.Mutex{}
	}
	return p.regMap[key]
}

// NextClient selects the next slot for upstreamID using round-robin and returns
// the associated Client together with the chosen slot index. The account is
// registered with the upstream CA on first use. Use NextClient when creating a
// new order so the slot is known and can be stored with the order.
func (p *Pool) NextClient(ctx context.Context, upstreamID string) (*Client, int, error) {
	p.mu.Lock()
	clients, err := p.getOrCreateAll(ctx, upstreamID)
	if err != nil {
		p.mu.Unlock()
		return nil, 0, err
	}
	n := len(clients)
	slot := p.nextSlot[upstreamID] % n
	p.nextSlot[upstreamID] = (slot + 1) % n
	client := clients[slot]
	p.mu.Unlock()

	if err := p.ensureSlotRegistered(ctx, upstreamID, slot, client); err != nil {
		return nil, 0, err
	}
	return client, slot, nil
}

// GetSlot returns the Client for a specific upstream and slot. Use this for all
// operations on an existing order (poll, authz, finalize, cert, revoke) where
// the slot was recorded when the order was created.
// If slot is out of range (e.g. a legacy order that predates multi-account
// support) it is clamped to 0.
func (p *Pool) GetSlot(ctx context.Context, upstreamID string, slot int) (*Client, error) {
	p.mu.Lock()
	clients, err := p.getOrCreateAll(ctx, upstreamID)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	if slot < 0 || slot >= len(clients) {
		slot = 0
	}
	client := clients[slot]
	p.mu.Unlock()
	return client, nil
}

// Get returns the slot-0 client for upstreamID. It exists for code paths that
// do not have a stored slot (e.g. the revocation fallback when the certificate
// issuer is unknown).
func (p *Pool) Get(ctx context.Context, upstreamID string) (*Client, error) {
	return p.GetSlot(ctx, upstreamID, 0)
}

// ensureSlotRegistered registers the client's ACME account if it has not yet
// been registered. Only one goroutine per (upstream, slot) pair performs the
// upstream HTTP round-trip; others wait and then reuse the result.
func (p *Pool) ensureSlotRegistered(ctx context.Context, upstreamID string, slot int, client *Client) error {
	if client.AccountURL() != "" {
		return nil // fast path
	}

	mu := p.slotRegLock(upstreamID, slot)
	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring the lock.
	if client.AccountURL() != "" {
		return nil
	}

	upCfg := p.cfg.Upstreams[upstreamID]
	accountURL, err := client.Register(ctx, upCfg.ContactEmail, upCfg.EAB)
	if err != nil {
		return fmt.Errorf("registering with %q slot %d: %w", upstreamID, slot, err)
	}

	keyPEM, err := client.KeyPEM()
	if err != nil {
		return err
	}
	ua := &model.UpstreamAccount{
		UpstreamID: upstreamID,
		Slot:       slot,
		AccountURL: accountURL,
		PrivateKey: string(keyPEM),
		CreatedAt:  time.Now().UTC(),
	}
	if err := p.store.SaveUpstreamAccount(ctx, ua); err != nil {
		return fmt.Errorf("persisting upstream account %q slot %d: %w", upstreamID, slot, err)
	}
	return nil
}

// getOrCreateAll is the internal (caller must hold p.mu) function that returns
// the full slice of Clients for an upstream, creating them if needed.
func (p *Pool) getOrCreateAll(ctx context.Context, upstreamID string) ([]*Client, error) {
	if cs, ok := p.clients[upstreamID]; ok {
		return cs, nil
	}

	upCfg, ok := p.cfg.Upstreams[upstreamID]
	if !ok {
		return nil, fmt.Errorf("upstream %q not in config", upstreamID)
	}

	count := upCfg.AccountCount
	if count < 1 {
		count = 1
	}

	clients := make([]*Client, count)
	for slot := 0; slot < count; slot++ {
		ua, err := p.store.GetUpstreamAccountBySlot(ctx, upstreamID, slot)
		if err != nil {
			return nil, fmt.Errorf("loading upstream account %q slot %d: %w", upstreamID, slot, err)
		}

		var key *ecdsa.PrivateKey
		if ua != nil {
			key, err = parseECPrivateKeyPEM([]byte(ua.PrivateKey))
			if err != nil {
				return nil, fmt.Errorf("parsing upstream key for %q slot %d: %w", upstreamID, slot, err)
			}
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generating upstream key: %w", err)
			}
		}

		var client *Client
		if upCfg.CACertPath != "" {
			hc, caErr := HTTPClientWithCACert(upCfg.CACertPath)
			if caErr != nil {
				return nil, fmt.Errorf("loading CA cert for upstream %q: %w", upstreamID, caErr)
			}
			client, err = NewWithHTTPClient(upCfg.DirectoryURL, key, hc)
		} else {
			client, err = New(upCfg.DirectoryURL, key)
		}
		if err != nil {
			return nil, err
		}
		if ua != nil {
			client.SetAccountURL(ua.AccountURL)
		}
		clients[slot] = client
	}

	p.clients[upstreamID] = clients
	return clients, nil
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
