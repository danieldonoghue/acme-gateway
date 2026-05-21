// Package store provides SQLite-backed persistence for the acme-gateway.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// Store wraps the SQLite database with ACME-domain operations.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at path and runs schema migrations.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// Serialise writes; WAL enables concurrent reads.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		return nil, fmt.Errorf("setting pragmas: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// PruneExpiredNonces removes nonces that have passed their expiry time.
func (s *Store) PruneExpiredNonces() error {
	_, err := s.db.Exec(`DELETE FROM nonces WHERE expires_at <= ?`, time.Now().UTC())
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id         TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  key_type   TEXT NOT NULL,
  contact    TEXT NOT NULL DEFAULT '[]',
  status     TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS upstream_accounts (
  upstream_id TEXT NOT NULL PRIMARY KEY,
  account_url TEXT NOT NULL,
  private_key TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id                 TEXT PRIMARY KEY,
  account_id         TEXT NOT NULL,
  upstream_id        TEXT NOT NULL,
  upstream_order_url TEXT NOT NULL,
  status             TEXT NOT NULL,
  identifiers        TEXT NOT NULL,
  profile            TEXT NOT NULL DEFAULT '',
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS resource_map (
  gateway_id    TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL,
  order_id      TEXT NOT NULL,
  upstream_url  TEXT NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS resource_map_upstream_url ON resource_map(upstream_url);

CREATE TABLE IF NOT EXISTS nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
`

func (s *Store) migrate() error {
	_, err := s.db.Exec(schema)
	return err
}
