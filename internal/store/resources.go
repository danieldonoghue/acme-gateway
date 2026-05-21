package store

import (
	"database/sql"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// SaveResource inserts a resource mapping. If a mapping for the same upstream_url
// already exists the existing gateway_id is preserved (idempotent).
func (s *Store) SaveResource(r *model.ResourceMap) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO resource_map (gateway_id, resource_type, order_id, upstream_url)
		 VALUES (?, ?, ?, ?)`,
		r.GatewayID, r.ResourceType, r.OrderID, r.UpstreamURL,
	)
	return err
}

// GetResource retrieves a resource mapping by its gateway-local ID.
// Returns nil, nil if not found.
func (s *Store) GetResource(gatewayID string) (*model.ResourceMap, error) {
	row := s.db.QueryRow(
		`SELECT gateway_id, resource_type, order_id, upstream_url
		 FROM resource_map WHERE gateway_id = ?`, gatewayID,
	)
	return scanResource(row)
}

// GetResourceByUpstreamURL retrieves a resource mapping by its upstream URL.
// Returns nil, nil if not found.
func (s *Store) GetResourceByUpstreamURL(upstreamURL string) (*model.ResourceMap, error) {
	row := s.db.QueryRow(
		`SELECT gateway_id, resource_type, order_id, upstream_url
		 FROM resource_map WHERE upstream_url = ?`, upstreamURL,
	)
	return scanResource(row)
}

func scanResource(row *sql.Row) (*model.ResourceMap, error) {
	var r model.ResourceMap
	if err := row.Scan(&r.GatewayID, &r.ResourceType, &r.OrderID, &r.UpstreamURL); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}
