package store

import (
	"context"
	"database/sql"

	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// SaveResource inserts a resource mapping. If a mapping for the same upstream_url
// already exists the existing gateway_id is preserved (idempotent).
func (s *Store) SaveResource(ctx context.Context, r *model.ResourceMap) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO resource_map (gateway_id, resource_type, order_id, upstream_url)
		 VALUES (?, ?, ?, ?)`,
		r.GatewayID, r.ResourceType, r.OrderID, r.UpstreamURL,
	)
	return err
}

// GetResource retrieves a resource mapping by its gateway-local ID.
// Returns nil, nil if not found.
func (s *Store) GetResource(ctx context.Context, gatewayID string) (*model.ResourceMap, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT gateway_id, resource_type, order_id, upstream_url, cert_fingerprint
		 FROM resource_map WHERE gateway_id = ?`, gatewayID,
	)
	return scanResource(row)
}

// GetResourceByUpstreamURL retrieves a resource mapping by its upstream URL.
// Returns nil, nil if not found.
func (s *Store) GetResourceByUpstreamURL(ctx context.Context, upstreamURL string) (*model.ResourceMap, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT gateway_id, resource_type, order_id, upstream_url, cert_fingerprint
		 FROM resource_map WHERE upstream_url = ?`, upstreamURL,
	)
	return scanResource(row)
}

// GetResourceByCertFingerprint retrieves a cert resource mapping by the SHA-256 fingerprint
// of the leaf certificate DER. Returns nil, nil if not found.
func (s *Store) GetResourceByCertFingerprint(ctx context.Context, fingerprint string) (*model.ResourceMap, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT gateway_id, resource_type, order_id, upstream_url, cert_fingerprint
		 FROM resource_map WHERE cert_fingerprint = ?`, fingerprint,
	)
	return scanResource(row)
}

// GetAuthzResourcesByOrderID returns all authorization resource mappings for an order.
func (s *Store) GetAuthzResourcesByOrderID(ctx context.Context, orderID string) ([]*model.ResourceMap, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT gateway_id, resource_type, order_id, upstream_url, cert_fingerprint
		 FROM resource_map WHERE order_id = ? AND resource_type = ?`,
		orderID, model.ResourceTypeAuthz,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*model.ResourceMap
	for rows.Next() {
		var r model.ResourceMap
		var fp sql.NullString
		if err := rows.Scan(&r.GatewayID, &r.ResourceType, &r.OrderID, &r.UpstreamURL, &fp); err != nil {
			return nil, err
		}
		if fp.Valid {
			r.CertFingerprint = fp.String
		}
		result = append(result, &r)
	}
	return result, rows.Err()
}

// UpdateResourceCertFingerprint stores the SHA-256 hex fingerprint of the leaf certificate
// against a cert resource entry, enabling revocation routing.
func (s *Store) UpdateResourceCertFingerprint(ctx context.Context, gatewayID, fingerprint string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE resource_map SET cert_fingerprint = ? WHERE gateway_id = ?`,
		fingerprint, gatewayID,
	)
	return err
}

func scanResource(row *sql.Row) (*model.ResourceMap, error) {
	var r model.ResourceMap
	var fp sql.NullString
	if err := row.Scan(&r.GatewayID, &r.ResourceType, &r.OrderID, &r.UpstreamURL, &fp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if fp.Valid {
		r.CertFingerprint = fp.String
	}
	return &r, nil
}
