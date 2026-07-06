package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

// probeKey is a single process-wide ECDSA key reused by all upstream health
// probes. Probes only issue unsigned directory GETs, so the key is never used
// to sign anything; sharing it avoids a fresh P-256 keygen per request (and per
// upstream) when /healthz/upstreams is polled. Returns nil only if keygen fails,
// in which case the caller falls back to per-call generation.
var probeKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	return k
})

// upstreamHealthTimeout bounds a single upstream directory probe. It is well
// under the server WriteTimeout so a slow/stalled upstream cannot hold the
// health request open indefinitely.
const upstreamHealthTimeout = 8 * time.Second

// livenessTimeout bounds the state-store ping in the k8s health probe.
const livenessTimeout = 2 * time.Second

// handleLiveness is a cheap health check for Kubernetes liveness/readiness
// probes. It verifies the process is serving and the local state store is
// reachable — deliberately WITHOUT touching upstream CAs, so a CA outage or
// rate-limit never causes Kubernetes to kill otherwise-healthy pods. Use
// GET /healthz/upstreams for the deeper (on-demand) upstream reachability view.
func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), livenessTimeout)
	defer cancel()

	if err := h.store.Ping(ctx); err != nil {
		h.log.Warn("liveness probe: state store unreachable", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unavailable",
			"reason": "state store unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// upstreamHealth is the per-upstream probe result.
type upstreamHealth struct {
	ID           string `json:"id"`
	DirectoryURL string `json:"directory_url"`
	Healthy      bool   `json:"healthy"`
	LatencyMS    int64  `json:"latency_ms"`
	NewOrderURL  string `json:"new_order_url,omitempty"`
	NewNonceURL  string `json:"new_nonce_url,omitempty"`
	Error        string `json:"error,omitempty"`
}

// upstreamsHealthResponse is the aggregate response for GET /healthz/upstreams.
type upstreamsHealthResponse struct {
	Status    string           `json:"status"` // "ok" | "degraded"
	CheckedAt string           `json:"checked_at"`
	Upstreams []upstreamHealth `json:"upstreams"`
}

// handleUpstreamsHealth probes every configured upstream by fetching its ACME
// directory and reports reachability + latency. It is a SHALLOW check: it does
// not create accounts or orders, so it carries no rate-limit risk and is safe
// to call on demand. A non-2xx aggregate status (503) is returned if any
// upstream is unreachable, so it can also drive alerting.
//
// This deliberately does not exercise finalize/issuance — that path can fail
// independently (e.g. a CA-side certificate-profile problem) while the
// directory is perfectly reachable, and issuance probes DO risk rate limits.
func (h *Handler) handleUpstreamsHealth(w http.ResponseWriter, r *http.Request) {
	// Not an ACME endpoint: no Replay-Nonce/Link headers here.
	ids := make([]string, 0, len(h.cfg.Upstreams))
	for id := range h.cfg.Upstreams {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	results := make([]upstreamHealth, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			results[i] = h.probeUpstream(r.Context(), id, h.cfg.Upstreams[id])
		}(i, id)
	}
	wg.Wait()

	allHealthy := true
	for _, res := range results {
		if !res.Healthy {
			allHealthy = false
			break
		}
	}

	status := "ok"
	code := http.StatusOK
	if !allHealthy {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}

	writeJSON(w, code, upstreamsHealthResponse{
		Status:    status,
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Upstreams: results,
	})
}

// probeUpstream fetches a single upstream's ACME directory using a throwaway
// client (no account, no persisted state) and returns a health result.
func (h *Handler) probeUpstream(ctx context.Context, id string, up config.UpstreamConfig) upstreamHealth {
	res := upstreamHealth{ID: id, DirectoryURL: up.DirectoryURL}

	client, err := h.newProbeClient(up)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, upstreamHealthTimeout)
	defer cancel()

	start := time.Now()
	dir, err := client.Directory(ctx)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		h.log.Warn("upstream health probe failed", "upstream_id", id, "directory_url", up.DirectoryURL, "err", err)
		return res
	}

	res.Healthy = true
	res.NewOrderURL = dir.NewOrder
	res.NewNonceURL = dir.NewNonce
	return res
}

// newProbeClient builds a throwaway upstream client honouring any configured
// private-CA trust anchor, without touching the account pool.
func (h *Handler) newProbeClient(up config.UpstreamConfig) (*upstream.Client, error) {
	if up.CACertPath != "" {
		httpClient, err := upstream.HTTPClientWithCACert(up.CACertPath)
		if err != nil {
			return nil, err
		}
		return upstream.NewWithHTTPClient(up.DirectoryURL, probeKey(), httpClient)
	}
	return upstream.New(up.DirectoryURL, probeKey())
}
