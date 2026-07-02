package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
	"github.com/danieldonoghue/acme-gateway/internal/store"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

func TestHandleCert_ExposesAlternateLinksAndRetrievesAlternateChain(t *testing.T) {
	t.Parallel()

	defaultChain := selfSignedCertPEM(t)
	altChain := selfSignedCertPEM(t)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   upstreamSrvURL("", r) + "/new-nonce",
				"newAccount": upstreamSrvURL("", r) + "/new-account",
				"newOrder":   upstreamSrvURL("", r) + "/new-order",
				"revokeCert": upstreamSrvURL("", r) + "/revoke-cert",
				"keyChange":  upstreamSrvURL("", r) + "/key-change",
			})
		case r.Method == http.MethodHead && r.URL.Path == "/new-nonce":
			w.Header().Set("Replay-Nonce", "nonce-1")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/acme/cert/default":
			w.Header().Set("Replay-Nonce", "nonce-2")
			w.Header().Add("Link", `<`+upstreamSrvURL("", r)+`/acme/cert/alt>;rel="alternate"`)
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(defaultChain)
		case r.Method == http.MethodPost && r.URL.Path == "/acme/cert/alt":
			w.Header().Set("Replay-Nonce", "nonce-3")
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(altChain)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstreamSrv.Close()

	st, pool, h := newCertTestHandler(t, upstreamSrv.URL)
	defer st.Close()

	ctx := context.Background()
	if err := st.SaveAccount(ctx, &model.Account{
		ID:        "acct-1",
		PublicKey: `{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`,
		KeyType:   model.KeyTypeECDSA,
		Status:    model.AccountStatusValid,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	keyPEM, err := upstream.GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}
	if err := st.SaveUpstreamAccount(ctx, &model.UpstreamAccount{
		UpstreamID: "le",
		Slot:       0,
		AccountURL: upstreamSrv.URL + "/acme/acct/1",
		PrivateKey: string(keyPEM),
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveUpstreamAccount: %v", err)
	}

	if err := st.SaveOrder(ctx, &model.Order{
		ID:               "order-1",
		AccountID:        "acct-1",
		UpstreamID:       "le",
		UpstreamSlot:     0,
		UpstreamOrderURL: upstreamSrv.URL + "/acme/order/1",
		Status:           model.OrderStatusValid,
		Identifiers:      `[{"type":"dns","value":"example.com"}]`,
		Profile:          "",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveOrder: %v", err)
	}

	if err := st.SaveResource(ctx, &model.ResourceMap{
		GatewayID:    "cert-default",
		ResourceType: model.ResourceTypeCert,
		OrderID:      "order-1",
		UpstreamURL:  upstreamSrv.URL + "/acme/cert/default",
	}); err != nil {
		t.Fatalf("SaveResource(default): %v", err)
	}

	r := chi.NewRouter()
	r.Get("/cert/{id}", h.handleCert)

	// Fetch the default certificate and verify alternate link passthrough.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://gw.example/cert/cert-default", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("default cert status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Body.Bytes(); string(got) != string(defaultChain) {
		t.Fatalf("default cert body mismatch")
	}

	altURL := findAlternateLink(rr.Result().Header.Values("Link"))
	if altURL == "" {
		t.Fatalf("expected Link rel=alternate header, got %v", rr.Result().Header.Values("Link"))
	}
	u, err := url.Parse(altURL)
	if err != nil {
		t.Fatalf("parse alternate URL: %v", err)
	}
	if !strings.HasPrefix(u.Path, "/cert/") {
		t.Fatalf("alternate URL path = %q, want /cert/{id}", u.Path)
	}

	// Fetch the alternate certificate through the gateway path.
	reqAlt := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://gw.example"+u.Path, nil)
	rrAlt := httptest.NewRecorder()
	r.ServeHTTP(rrAlt, reqAlt)
	if rrAlt.Code != http.StatusOK {
		t.Fatalf("alternate cert status = %d, want 200 body=%s", rrAlt.Code, rrAlt.Body.String())
	}
	if got := rrAlt.Body.Bytes(); string(got) != string(altChain) {
		t.Fatalf("alternate cert body mismatch")
	}

	// Ensure pool was exercised and upstream client could resolve for slot-based order.
	if _, err := pool.GetSlot(context.Background(), "le", 0); err != nil {
		t.Fatalf("pool GetSlot after requests: %v", err)
	}
}

func newCertTestHandler(t *testing.T, upstreamBaseURL string) (*store.Store, *upstream.Pool, *Handler) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{BaseURL: "https://gw.example"},
		Upstreams: map[string]config.UpstreamConfig{
			"le": {
				DirectoryURL: upstreamBaseURL + "/directory",
				ContactEmail: "ops@example.com",
			},
		},
		Routing: config.RoutingConfig{DefaultUpstream: "le"},
	}
	pool := upstream.NewPool(cfg, st)
	h := &Handler{
		cfg:   cfg,
		store: st,
		pool:  pool,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return st, pool, h
}

func findAlternateLink(links []string) string {
	for _, v := range links {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if !strings.Contains(strings.ToLower(p), `rel="alternate"`) {
				continue
			}
			if !strings.HasPrefix(p, "<") {
				continue
			}
			end := strings.IndexByte(p, '>')
			if end <= 1 {
				continue
			}
			return p[1:end]
		}
	}
	return ""
}

func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: newSerial(t)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	return serial
}

func upstreamSrvURL(path string, r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if path == "" {
		return scheme + "://" + r.Host
	}
	return scheme + "://" + r.Host + path
}
