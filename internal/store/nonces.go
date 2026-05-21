package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

const nonceTTL = 10 * time.Minute

// IssueNonce generates a cryptographically random nonce, persists it, and returns it.
func (s *Store) IssueNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(b)
	expiresAt := time.Now().Add(nonceTTL).UTC()

	if _, err := s.db.Exec(
		`INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)`,
		value, expiresAt.Format(time.RFC3339),
	); err != nil {
		return "", fmt.Errorf("saving nonce: %w", err)
	}
	return value, nil
}

// ConsumeNonce validates and atomically deletes a nonce.
// Returns an error if the nonce is unknown or expired.
func (s *Store) ConsumeNonce(value string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var n model.Nonce
	var expiresAt string
	err = tx.QueryRow(
		`SELECT nonce, expires_at FROM nonces WHERE nonce = ?`, value,
	).Scan(&n.Value, &expiresAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("nonce not found")
	}
	if err != nil {
		return err
	}

	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return fmt.Errorf("parsing nonce expiry: %w", err)
	}
	if time.Now().After(t) {
		// Delete the expired nonce and report it as invalid.
		tx.Exec(`DELETE FROM nonces WHERE nonce = ?`, value) //nolint:errcheck
		tx.Commit()                                          //nolint:errcheck
		return fmt.Errorf("nonce expired")
	}

	if _, err := tx.Exec(`DELETE FROM nonces WHERE nonce = ?`, value); err != nil {
		return err
	}
	return tx.Commit()
}
