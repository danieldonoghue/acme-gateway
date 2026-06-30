package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// TestBusyTimeoutOnAllConnections guards the regression where busy_timeout was
// set with a one-off PRAGMA and therefore applied to only one pooled
// connection, leaving the rest at busy_timeout=0 (instant SQLITE_BUSY under
// concurrency). Holding several connections open at once forces the pool to
// open distinct connections; every one must report the configured timeout.
func TestBusyTimeoutOnAllConnections(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "pragma.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck

	ctx := context.Background()
	const n = 5
	conns := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := s.db.Conn(ctx)
		if err != nil {
			t.Fatalf("opening connection %d: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Close() }) // released even if a later check fails
		conns = append(conns, c)
	}

	for i, c := range conns {
		var busyTimeout int
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			t.Fatalf("conn %d: reading busy_timeout: %v", i, err)
		}
		if busyTimeout < 1000 {
			t.Errorf("conn %d: busy_timeout=%d, want >= 1000 (pragma not applied pool-wide)", i, busyTimeout)
		}
	}
}
