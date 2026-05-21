package store

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// SaveOrder inserts or replaces an order record.
func (s *Store) SaveOrder(o *model.Order) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO orders
		 (id, account_id, upstream_id, upstream_order_url, status, identifiers, profile, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.AccountID, o.UpstreamID, o.UpstreamOrderURL,
		o.Status, o.Identifiers, o.Profile,
		o.CreatedAt.UTC().Format(time.RFC3339),
		o.UpdatedAt.UTC().Format(time.RFC3339),
	)
	return err
}

// GetOrder retrieves an order by its gateway ID. Returns nil, nil if not found.
func (s *Store) GetOrder(id string) (*model.Order, error) {
	row := s.db.QueryRow(
		`SELECT id, account_id, upstream_id, upstream_order_url, status, identifiers, profile, created_at, updated_at
		 FROM orders WHERE id = ?`, id,
	)
	return scanOrder(row)
}

// UpdateOrderStatus updates the status and updated_at timestamp for an order.
func (s *Store) UpdateOrderStatus(id, status string) error {
	result, err := s.db.Exec(
		`UPDATE orders SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), id,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("order %q not found", id)
	}
	return nil
}

func scanOrder(row *sql.Row) (*model.Order, error) {
	var o model.Order
	var createdAt, updatedAt string
	if err := row.Scan(
		&o.ID, &o.AccountID, &o.UpstreamID, &o.UpstreamOrderURL,
		&o.Status, &o.Identifiers, &o.Profile, &createdAt, &updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &o, nil
}
