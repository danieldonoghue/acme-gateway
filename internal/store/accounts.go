package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// SaveAccount inserts or replaces an account record.
func (s *Store) SaveAccount(ctx context.Context, a *model.Account) error {
	contact, err := json.Marshal(a.Contact)
	if err != nil {
		return fmt.Errorf("marshalling contact: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO accounts (id, public_key, key_type, contact, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.PublicKey, a.KeyType, string(contact), a.Status, a.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetAccount retrieves an account by its thumbprint ID. Returns nil, nil if not found.
func (s *Store) GetAccount(ctx context.Context, id string) (*model.Account, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, public_key, key_type, contact, status, created_at FROM accounts WHERE id = ?`, id,
	)
	return scanAccount(row)
}

func scanAccount(row *sql.Row) (*model.Account, error) {
	var a model.Account
	var contact, createdAt string
	if err := row.Scan(&a.ID, &a.PublicKey, &a.KeyType, &contact, &a.Status, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(contact), &a.Contact); err != nil {
		a.Contact = nil
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t, _ = time.Parse("2006-01-02 15:04:05+00:00", createdAt) //nolint:errcheck
	}
	a.CreatedAt = t
	return &a, nil
}

// SaveUpstreamAccount inserts or replaces the gateway's account at an upstream CA.
func (s *Store) SaveUpstreamAccount(ctx context.Context, ua *model.UpstreamAccount) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO upstream_accounts (upstream_id, slot, account_url, private_key, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		ua.UpstreamID, ua.Slot, ua.AccountURL, ua.PrivateKey, ua.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetUpstreamAccountBySlot retrieves the gateway's account for a specific upstream and slot.
// Returns nil, nil if not found.
func (s *Store) GetUpstreamAccountBySlot(ctx context.Context, upstreamID string, slot int) (*model.UpstreamAccount, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT upstream_id, slot, account_url, private_key, created_at
		 FROM upstream_accounts WHERE upstream_id = ? AND slot = ?`, upstreamID, slot,
	)
	return scanUpstreamAccount(row)
}

func scanUpstreamAccount(row *sql.Row) (*model.UpstreamAccount, error) {
	var ua model.UpstreamAccount
	var createdAt string
	if err := row.Scan(&ua.UpstreamID, &ua.Slot, &ua.AccountURL, &ua.PrivateKey, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t, _ = time.Parse("2006-01-02 15:04:05+00:00", createdAt) //nolint:errcheck
	}
	ua.CreatedAt = t
	return &ua, nil
}
