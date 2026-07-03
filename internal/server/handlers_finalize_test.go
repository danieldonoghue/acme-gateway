package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
	"github.com/danieldonoghue/acme-gateway/internal/router"
	"github.com/danieldonoghue/acme-gateway/internal/store"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

// finalizeTestEnv wires a store, upstream stub, and handler with a routing
// rule that requires RSA CSRs for profile "tlsclient-rsa".
type finalizeTestEnv struct {
	st      *store.Store
	handler *Handler
	acctKey *ecdsa.PrivateKey
	baseURL string
	// finalizeHits counts upstream finalize calls. finalizeStatus, when set to
	// a non-zero HTTP status, makes the upstream finalize stub return that
	// status with an ACME problem document instead of "processing".
	finalizeHits   *atomic.Int64
	finalizeStatus *atomic.Int64
}

func newFinalizeTestEnv(t *testing.T) *finalizeTestEnv {
	t.Helper()

	var hits, finalizeStatus atomic.Int64
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/directory":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srvURL + "/new-nonce",
				"newAccount": srvURL + "/new-account",
				"newOrder":   srvURL + "/new-order",
				"revokeCert": srvURL + "/revoke-cert",
				"keyChange":  srvURL + "/key-change",
			})
		case r.Method == http.MethodHead && r.URL.Path == "/new-nonce":
			w.Header().Set("Replay-Nonce", "up-nonce")
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/acme/finalize/1":
			hits.Add(1)
			w.Header().Set("Replay-Nonce", "up-nonce-2")
			if code := finalizeStatus.Load(); code != 0 {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(int(code))
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   "urn:ietf:params:acme:error:serverInternal",
					"detail": "stubbed finalize failure",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":   "processing",
				"finalize": srvURL + "/acme/finalize/1",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	srvURL = srv.URL

	st, err := store.New(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := &config.Config{
		Server: config.ServerConfig{BaseURL: "https://gw.example"},
		Upstreams: map[string]config.UpstreamConfig{
			"private-ca-rsa": {DirectoryURL: srv.URL + "/directory"},
		},
		Routing: config.RoutingConfig{
			Rules: []config.RoutingRule{
				{
					Match:             config.MatchConfig{Profile: "tlsclient-rsa"},
					Upstream:          "private-ca-rsa",
					RequireCSRKeyType: "RSA",
				},
			},
			DefaultUpstream: "private-ca-rsa",
		},
	}

	h := &Handler{
		cfg:    cfg,
		store:  st,
		router: router.New(&cfg.Routing),
		pool:   upstream.NewPool(cfg, st),
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	ctx := context.Background()
	acctKey := newTestKey(t)
	jwkJSON, err := json.Marshal(jose.JSONWebKey{Key: acctKey.Public()})
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	if err := st.SaveAccount(ctx, &model.Account{
		ID:        "acct-1",
		PublicKey: string(jwkJSON),
		KeyType:   model.KeyTypeECDSA,
		Status:    model.AccountStatusValid,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	upKeyPEM, err := upstream.GenerateKeyPEM()
	if err != nil {
		t.Fatalf("GenerateKeyPEM: %v", err)
	}
	if err := st.SaveUpstreamAccount(ctx, &model.UpstreamAccount{
		UpstreamID: "private-ca-rsa",
		Slot:       0,
		AccountURL: srv.URL + "/acme/acct/1",
		PrivateKey: string(upKeyPEM),
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveUpstreamAccount: %v", err)
	}

	if err := st.SaveOrder(ctx, &model.Order{
		ID:               "order-1",
		AccountID:        "acct-1",
		UpstreamID:       "private-ca-rsa",
		UpstreamSlot:     0,
		UpstreamOrderURL: srv.URL + "/acme/order/1",
		Status:           model.OrderStatusReady,
		Identifiers:      `[{"type":"dns","value":"host.example.com"}]`,
		Profile:          "tlsclient-rsa",
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveOrder: %v", err)
	}

	if err := st.SaveResource(ctx, &model.ResourceMap{
		GatewayID:    "fin-1",
		ResourceType: model.ResourceTypeFinalize,
		OrderID:      "order-1",
		UpstreamURL:  srv.URL + "/acme/finalize/1",
	}); err != nil {
		t.Fatalf("SaveResource: %v", err)
	}

	return &finalizeTestEnv{
		st:             st,
		handler:        h,
		acctKey:        acctKey,
		baseURL:        "https://gw.example",
		finalizeHits:   &hits,
		finalizeStatus: &finalizeStatus,
	}
}

// postFinalize signs and POSTs a finalize request for the given CSR DER.
func (env *finalizeTestEnv) postFinalize(t *testing.T, csrDER []byte) *httptest.ResponseRecorder {
	t.Helper()

	nonce, err := env.st.IssueNonce(context.Background())
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}

	payload := fmt.Sprintf(`{"csr":%q}`, base64.RawURLEncoding.EncodeToString(csrDER))
	jws := buildTestJWS(t, env.acctKey, []byte(payload), nonce,
		env.baseURL+"/finalize/fin-1", env.baseURL+"/account/acct-1")

	r := chi.NewRouter()
	r.Post("/finalize/{id}", env.handler.handleFinalize)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		env.baseURL+"/finalize/fin-1", strings.NewReader(string(jws)))
	req.Header.Set("Content-Type", "application/jose+json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func testCSR(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "host.example.com"},
		DNSNames: []string{"host.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return der
}

func TestHandleFinalize_RejectsWrongCSRKeyType(t *testing.T) {
	env := newFinalizeTestEnv(t)

	rr := env.postFinalize(t, testCSR(t, newTestKey(t))) // ECDSA CSR, rule requires RSA

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rr.Code, rr.Body.String())
	}
	var prob struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("decoding problem document: %v", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:badCSR" {
		t.Errorf("problem type = %q, want badCSR", prob.Type)
	}
	if !strings.Contains(prob.Detail, "RSA") {
		t.Errorf("detail %q should mention required key type", prob.Detail)
	}
	if got := env.finalizeHits.Load(); got != 0 {
		t.Errorf("upstream finalize hit %d times, want 0 (rejected before proxying)", got)
	}
}

func TestHandleFinalize_RejectsUnparseableCSR(t *testing.T) {
	env := newFinalizeTestEnv(t)

	rr := env.postFinalize(t, []byte("not a valid der csr")) // undecodable CSR

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", rr.Code, rr.Body.String())
	}
	var prob struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("decoding problem document: %v", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:badCSR" {
		t.Errorf("problem type = %q, want badCSR", prob.Type)
	}
	if got := env.finalizeHits.Load(); got != 0 {
		t.Errorf("upstream finalize hit %d times, want 0 (rejected before proxying)", got)
	}
}

func TestHandleFinalize_AcceptsMatchingCSRKeyType(t *testing.T) {
	env := newFinalizeTestEnv(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	rr := env.postFinalize(t, testCSR(t, rsaKey))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	if got := env.finalizeHits.Load(); got != 1 {
		t.Errorf("upstream finalize hit %d times, want 1", got)
	}
}

// rsaCSR builds a valid RSA CSR that passes the require_csr_key_type=RSA rule,
// so finalize proxies upstream and we can exercise the rejection handling.
func rsaCSR(t *testing.T) []byte {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return testCSR(t, rsaKey)
}

func TestHandleFinalize_DefinitiveUpstreamRejectionInvalidatesOrder(t *testing.T) {
	env := newFinalizeTestEnv(t)
	env.finalizeStatus.Store(http.StatusForbidden) // 403: definitive rejection

	rr := env.postFinalize(t, rsaCSR(t))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (relayed) body=%s", rr.Code, rr.Body.String())
	}
	order, err := env.st.GetOrder(context.Background(), "order-1")
	if err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	if order.Status != model.OrderStatusInvalid {
		t.Errorf("order status = %q, want invalid (definitive rejection should be terminal)", order.Status)
	}
}

func TestHandleFinalize_TransientUpstreamErrorDoesNotInvalidateOrder(t *testing.T) {
	env := newFinalizeTestEnv(t)
	env.finalizeStatus.Store(http.StatusTooManyRequests) // 429: transient

	rr := env.postFinalize(t, rsaCSR(t))

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (relayed) body=%s", rr.Code, rr.Body.String())
	}
	order, err := env.st.GetOrder(context.Background(), "order-1")
	if err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	if order.Status != model.OrderStatusReady {
		t.Errorf("order status = %q, want ready (transient error must not invalidate)", order.Status)
	}
}
