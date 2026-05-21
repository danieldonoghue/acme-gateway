package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// SaveAccount inserts or replaces an account record.
func (s *Store) SaveAccount(a *model.Account) error {
	contact, err := json.Marshal(a.Contact)
	if err != nil {
		return fmt.Errorf("marshalling contact: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO accounts (id, public_key, key_type, contact, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.PublicKey, a.KeyType, string(contact), a.Status, a.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetAccount retrieves an account by its thumbprint ID. Returns nil, nil if not found.
func (s *Store) GetAccount(id string) (*model.Account, error) {
	row := s.db.QueryRow(
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
		t, _ = time.Parse("2006-01-02 15:04:05+00:00", createdAt)
	}
	a.CreatedAt = t
	return &a, nil
}

// SaveUpstreamAccount inserts or replaces the gateway's account at an upstream CA.
func (s *Store) SaveUpstreamAccount(ua *model.UpstreamAccount) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO upstream_accounts (upstream_id, account_url, private_key, created_at)
		 VALUES (?, ?, ?, ?)`,
		ua.UpstreamID, ua.AccountURL, ua.PrivateKey, ua.CreatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetUpstreamAccount retrieves the gateway's account for the given upstream ID.
// Returns nil, nil if not found.
func (s *Store) GetUpstreamAccount(upstreamID string) (*model.UpstreamAccount, error) {
	row := s.db.QueryRow(
		`SELECT upstream_id, account_url, private_key, created_at
		 FROM upstream_accounts WHERE upstream_id = ?`, upstreamID,
	)
	var ua model.UpstreamAccount
	var createdAt string
	if err := row.Scan(&ua.UpstreamID, &ua.AccountURL, &ua.PrivateKey, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t, _ = time.Parse("2006-01-02 15:04:05+00:00", createdAt)
	}
	ua.CreatedAt = t
	return &ua, nil
}
