package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/store"
)

func TestHandleLiveness(t *testing.T) {
	t.Parallel()

	st, err := store.New(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	h := &Handler{store: st, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Healthy: store reachable → 200.
	rr := httptest.NewRecorder()
	h.handleLiveness(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthy liveness = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	// Store closed → ping fails → 503, so k8s can restart the pod.
	_ = st.Close()
	rr = httptest.NewRecorder()
	h.handleLiveness(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy liveness = %d, want 503", rr.Code)
	}
}

func TestHandleUpstreamsHealth(t *testing.T) {
	t.Parallel()

	// A reachable upstream that serves a valid ACME directory.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/directory" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce": r.Host + "/new-nonce",
				"newOrder": r.Host + "/new-order",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer up.Close()

	h := &Handler{
		cfg: &config.Config{
			Server: config.ServerConfig{BaseURL: "https://gw.example"},
			Upstreams: map[string]config.UpstreamConfig{
				"live": {DirectoryURL: up.URL + "/directory"},
				// Unroutable address → probe fails fast within the timeout.
				"dead": {DirectoryURL: "http://127.0.0.1:1/directory"},
			},
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://gw.example/healthz/upstreams", nil)
	rr := httptest.NewRecorder()
	h.handleUpstreamsHealth(rr, req)

	// One upstream is down, so the aggregate must report 503/degraded.
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}

	var resp upstreamsHealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "degraded" {
		t.Fatalf("status field = %q, want degraded", resp.Status)
	}
	if len(resp.Upstreams) != 2 {
		t.Fatalf("got %d upstreams, want 2", len(resp.Upstreams))
	}

	byID := map[string]upstreamHealth{}
	for _, u := range resp.Upstreams {
		byID[u.ID] = u
	}
	if !byID["live"].Healthy {
		t.Errorf("live upstream should be healthy: %+v", byID["live"])
	}
	if byID["live"].NewOrderURL == "" {
		t.Errorf("live upstream should expose new_order_url")
	}
	if byID["dead"].Healthy {
		t.Errorf("dead upstream should be unhealthy")
	}
	if byID["dead"].Error == "" {
		t.Errorf("dead upstream should carry an error message")
	}
}
