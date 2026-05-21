// Package store provides SQLite-backed persistence for the acme-gateway.
package store

import (
	"context"
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

	// WAL mode: allow a small connection pool so concurrent reads proceed in
	// parallel. Writes still serialise at the SQLite level; busy_timeout gives
	// writers a retry budget instead of failing immediately with SQLITE_BUSY.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	if _, err := db.ExecContext(context.Background(), `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		return nil, fmt.Errorf("setting pragmas: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// PruneExpiredNonces removes nonces that have passed their expiry time.
func (s *Store) PruneExpiredNonces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM nonces WHERE expires_at <= ?`, time.Now().UTC())
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
  upstream_id TEXT    NOT NULL,
  slot        INTEGER NOT NULL DEFAULT 0,
  account_url TEXT    NOT NULL,
  private_key TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  PRIMARY KEY (upstream_id, slot)
);

CREATE TABLE IF NOT EXISTS orders (
  id                 TEXT    PRIMARY KEY,
  account_id         TEXT    NOT NULL,
  upstream_id        TEXT    NOT NULL,
  upstream_slot      INTEGER NOT NULL DEFAULT 0,
  upstream_order_url TEXT    NOT NULL,
  status             TEXT    NOT NULL,
  identifiers        TEXT    NOT NULL,
  profile            TEXT    NOT NULL DEFAULT '',
  created_at         TEXT    NOT NULL,
  updated_at         TEXT    NOT NULL,
  FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS resource_map (
  gateway_id       TEXT PRIMARY KEY,
  resource_type    TEXT NOT NULL,
  order_id         TEXT NOT NULL,
  upstream_url     TEXT NOT NULL,
  cert_fingerprint TEXT,
  FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS resource_map_upstream_url ON resource_map(upstream_url);

CREATE TABLE IF NOT EXISTS nonces (
  nonce      TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.ExecContext(context.Background(), schema); err != nil {
		return err
	}
	// Idempotent column additions for databases predating this schema version.
	s.db.ExecContext(context.Background(), `ALTER TABLE resource_map ADD COLUMN cert_fingerprint TEXT`)              //nolint:errcheck,gosec
	s.db.ExecContext(context.Background(), `ALTER TABLE orders ADD COLUMN upstream_slot INTEGER NOT NULL DEFAULT 0`) //nolint:errcheck,gosec
	// Migrate upstream_accounts from single-PK to composite (upstream_id, slot) PK.
	// Detect the old schema by checking whether the slot column exists.
	var slotExists int
	s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('upstream_accounts') WHERE name='slot'`).Scan(&slotExists) //nolint:errcheck,gosec
	if slotExists == 0 {
		// Wrap in a transaction so a crash mid-swap doesn't orphan data.
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return fmt.Errorf("beginning upstream_accounts migration: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), `ALTER TABLE upstream_accounts RENAME TO upstream_accounts_v1`); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("renaming upstream_accounts: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), `CREATE TABLE upstream_accounts (
  upstream_id TEXT    NOT NULL,
  slot        INTEGER NOT NULL DEFAULT 0,
  account_url TEXT    NOT NULL,
  private_key TEXT    NOT NULL,
  created_at  TEXT    NOT NULL,
  PRIMARY KEY (upstream_id, slot)
)`); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("creating upstream_accounts: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO upstream_accounts SELECT upstream_id,0,account_url,private_key,created_at FROM upstream_accounts_v1`); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("copying upstream_accounts data: %w", err)
		}
		if _, err := tx.ExecContext(context.Background(), `DROP TABLE upstream_accounts_v1`); err != nil {
			tx.Rollback() //nolint:errcheck,gosec
			return fmt.Errorf("dropping upstream_accounts_v1: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing upstream_accounts migration: %w", err)
		}
	}
	return nil
}
