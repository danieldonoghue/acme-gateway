package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
	"github.com/danieldonoghue/acme-gateway/internal/router"
	"github.com/danieldonoghue/acme-gateway/internal/store"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

// Handler holds the dependencies needed by all ACME endpoint handlers.
type Handler struct {
	cfg    *config.Config
	store  *store.Store
	router *router.Router
	pool   *upstream.Pool
	log    *slog.Logger
}

// NewHandler creates a Handler with the given dependencies.
func NewHandler(cfg *config.Config, st *store.Store, r *router.Router, pool *upstream.Pool, log *slog.Logger) *Handler {
	return &Handler{cfg: cfg, store: st, router: r, pool: pool, log: log}
}

// ─── ACME error types ─────────────────────────────────────────────────────────

type acmeError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e *acmeError) Error() string { return e.Detail }

func errBadNonce(detail string) *acmeError {
	return &acmeError{Type: "urn:ietf:params:acme:error:badNonce", Detail: detail, Status: http.StatusBadRequest}
}
func errMalformed(detail string) *acmeError {
	return &acmeError{Type: "urn:ietf:params:acme:error:malformed", Detail: detail, Status: http.StatusBadRequest}
}
func errUnauthorized(detail string) *acmeError {
	return &acmeError{Type: "urn:ietf:params:acme:error:unauthorized", Detail: detail, Status: http.StatusUnauthorized}
}
func errNotFound(detail string) *acmeError {
	return &acmeError{Type: "urn:ietf:params:acme:error:malformed", Detail: detail, Status: http.StatusNotFound}
}
func errServerInternal(detail string) *acmeError {
	return &acmeError{Type: "urn:ietf:params:acme:error:serverInternal", Detail: detail, Status: http.StatusInternalServerError}
}

// writeError writes an ACME problem document and attaches a fresh Replay-Nonce.
func (h *Handler) writeError(w http.ResponseWriter, e *acmeError) {
	h.attachNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(e) //nolint:errcheck,gosec
}

// attachNonce issues a fresh nonce and sets it as the Replay-Nonce response header.
func (h *Handler) attachNonce(w http.ResponseWriter) {
	if n, err := h.store.IssueNonce(context.Background()); err == nil {
		w.Header().Set("Replay-Nonce", n)
	}
}

// linkHeader returns the Link header value pointing at the directory.
func (h *Handler) linkHeader() string {
	return fmt.Sprintf(`<%s/directory>;rel="index"`, h.cfg.Server.BaseURL)
}

// addCommonHeaders adds Replay-Nonce and Link headers to every response.
func (h *Handler) addCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("Link", h.linkHeader())
	h.attachNonce(w)
}

// ─── Nonce ────────────────────────────────────────────────────────────────────

// handleNewNonce serves HEAD /new-nonce and GET /new-nonce (RFC 8555 §7.2).
func (h *Handler) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	h.attachNonce(w)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── JWS helpers ──────────────────────────────────────────────────────────────

// parseAndValidateJWS reads, parses, and structurally validates an inbound ACME POST.
// It checks the URL header matches the request and consumes the nonce.
// It does NOT verify the signature (callers must call parsed.VerifySignature).
func (h *Handler) parseAndValidateJWS(w http.ResponseWriter, r *http.Request) (*ParsedJWS, bool) {
	if r.Header.Get("Content-Type") != "application/jose+json" {
		h.writeError(w, errMalformed("Content-Type must be application/jose+json"))
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		h.writeError(w, errMalformed("reading request body"))
		return nil, false
	}

	parsed, err := ParseJWS(body)
	if err != nil {
		h.writeError(w, errMalformed(err.Error()))
		return nil, false
	}

	// Validate the url header matches this request's URL.
	requestURL := h.cfg.Server.BaseURL + r.URL.Path
	if parsed.URL != requestURL {
		h.writeError(w, errMalformed(fmt.Sprintf("JWS url %q does not match request URL %q", parsed.URL, requestURL)))
		return nil, false
	}

	// Consume the nonce (single-use).
	if err := h.store.ConsumeNonce(r.Context(), parsed.Nonce); err != nil {
		h.writeError(w, errBadNonce(err.Error()))
		return nil, false
	}

	return parsed, true
}

// resolveAccount looks up the account from the KID or embedded JWK.
// For new-account (embeddedJWK != nil), it returns the existing account if found.
func (h *Handler) resolveAccount(ctx context.Context, parsed *ParsedJWS) (*model.Account, *acmeError) {
	if parsed.EmbeddedJWK != nil {
		tp, err := JWKThumbprint(parsed.EmbeddedJWK)
		if err != nil {
			return nil, errMalformed("invalid JWK: " + err.Error())
		}
		acct, err := h.store.GetAccount(ctx, tp)
		if err != nil {
			return nil, errServerInternal("looking up account")
		}
		return acct, nil // may be nil (new account)
	}

	// KID = full account URL, e.g. https://gw/account/thumbprint
	kid := parsed.AccountKID
	prefix := h.cfg.Server.BaseURL + "/account/"
	if !strings.HasPrefix(kid, prefix) {
		return nil, errUnauthorized("kid does not reference a known account URL")
	}
	acctID := strings.TrimPrefix(kid, prefix)

	acct, err := h.store.GetAccount(ctx, acctID)
	if err != nil {
		return nil, errServerInternal("looking up account")
	}
	if acct == nil {
		return nil, errUnauthorized("account not found")
	}
	return acct, nil
}

// ─── POST /new-account ────────────────────────────────────────────────────────

type newAccountRequest struct {
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
}

type accountResponse struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders"`
}

func (h *Handler) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	if parsed.EmbeddedJWK == nil {
		h.writeError(w, errMalformed("new-account must use jwk, not kid"))
		return
	}

	var req newAccountRequest
	if len(parsed.Payload) > 0 {
		if err := json.Unmarshal(parsed.Payload, &req); err != nil {
			h.writeError(w, errMalformed("invalid account payload"))
			return
		}
	}

	tp, err := JWKThumbprint(parsed.EmbeddedJWK)
	if err != nil {
		h.writeError(w, errMalformed("invalid JWK"))
		return
	}

	// Verify the JWS signature before doing anything meaningful.
	if err := parsed.VerifySignature(parsed.EmbeddedJWK.Key); err != nil {
		h.writeError(w, errUnauthorized("signature verification failed"))
		return
	}

	existing, err := h.store.GetAccount(r.Context(), tp)
	if err != nil {
		h.writeError(w, errServerInternal("looking up account"))
		return
	}

	accountURL := h.cfg.Server.BaseURL + "/account/" + tp

	if existing != nil {
		// RFC 8555 §7.3: return 200 for existing accounts.
		w.Header().Set("Location", accountURL)
		writeJSON(w, http.StatusOK, &accountResponse{
			Status:  existing.Status,
			Contact: existing.Contact,
			Orders:  accountURL + "/orders",
		})
		return
	}

	if req.OnlyReturnExisting {
		h.writeError(w, &acmeError{
			Type:   "urn:ietf:params:acme:error:accountDoesNotExist",
			Detail: "account does not exist",
			Status: http.StatusBadRequest,
		})
		return
	}

	kt, err := KeyTypeFromJWK(parsed.EmbeddedJWK)
	if err != nil {
		h.writeError(w, errMalformed("unsupported key type"))
		return
	}

	jwkJSON, err := json.Marshal(parsed.EmbeddedJWK)
	if err != nil {
		h.writeError(w, errServerInternal("marshalling key"))
		return
	}

	acct := &model.Account{
		ID:        tp,
		PublicKey: string(jwkJSON),
		KeyType:   kt,
		Contact:   req.Contact,
		Status:    model.AccountStatusValid,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.SaveAccount(r.Context(), acct); err != nil {
		h.writeError(w, errServerInternal("saving account"))
		return
	}

	h.log.Info("account created", "account_id", tp, "key_type", kt)

	w.Header().Set("Location", accountURL)
	writeJSON(w, http.StatusCreated, &accountResponse{
		Status:  acct.Status,
		Contact: acct.Contact,
		Orders:  accountURL + "/orders",
	})
}

// ─── POST /new-order ──────────────────────────────────────────────────────────

type newOrderRequest struct {
	Identifiers []model.Identifier `json:"identifiers"`
	Profile     string             `json:"profile,omitempty"`
}

type orderResponse struct {
	Status         string             `json:"status"`
	Expires        string             `json:"expires,omitempty"`
	Identifiers    []model.Identifier `json:"identifiers"`
	Authorizations []string           `json:"authorizations"`
	Finalize       string             `json:"finalize"`
	Certificate    string             `json:"certificate,omitempty"`
	Error          interface{}        `json:"error,omitempty"`
}

func (h *Handler) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	if parsed.EmbeddedJWK != nil {
		h.writeError(w, errMalformed("new-order requires kid, not jwk"))
		return
	}

	acct, aerr := h.resolveAccount(r.Context(), parsed)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}
	if err := parsed.VerifySignature(h.mustParsePublicKey(acct.PublicKey)); err != nil {
		h.writeError(w, errUnauthorized("signature verification failed"))
		return
	}

	var req newOrderRequest
	if err := json.Unmarshal(parsed.Payload, &req); err != nil {
		h.writeError(w, errMalformed("invalid order payload"))
		return
	}
	if len(req.Identifiers) == 0 {
		h.writeError(w, errMalformed("identifiers must not be empty"))
		return
	}

	// ── Routing decision ──────────────────────────────────────────────────────
	decision := h.router.Route(&router.Request{
		Profile:     req.Profile,
		KeyType:     acct.KeyType,
		Identifiers: req.Identifiers,
	})
	if decision.UpstreamID == "" {
		h.writeError(w, errServerInternal("no upstream matched and no default configured"))
		return
	}
	upstreamProfile := router.ResolveUpstreamProfile(decision, req.Profile)

	// Ensure the gateway has an account at this upstream and select a slot for
	// this order using round-robin across the upstream's account pool.
	client, slot, err := h.pool.NextClient(r.Context(), decision.UpstreamID)
	if err != nil {
		h.log.Error("upstream account error", "upstream", decision.UpstreamID, "err", err)
		h.writeError(w, errServerInternal("upstream account unavailable"))
		return
	}

	// Convert identifiers for the upstream client.
	upstreamIDs := make([]upstream.Identifier, len(req.Identifiers))
	for i, id := range req.Identifiers {
		upstreamIDs[i] = upstream.Identifier{Type: id.Type, Value: id.Value}
	}

	start := time.Now()
	upOrder, upOrderURL, err := client.SubmitOrder(r.Context(), upstreamIDs, upstreamProfile)
	if err != nil {
		h.log.Error("upstream order failed", "upstream", decision.UpstreamID, "err", err)
		h.writeError(w, errServerInternal("upstream order failed: "+err.Error()))
		return
	}

	// Persist order
	orderID := uuid.New().String()
	idJSON, err := json.Marshal(req.Identifiers)
	if err != nil {
		h.writeError(w, errServerInternal("marshalling identifiers"))
		return
	}

	order := &model.Order{
		ID:               orderID,
		AccountID:        acct.ID,
		UpstreamID:       decision.UpstreamID,
		UpstreamSlot:     slot,
		UpstreamOrderURL: upOrderURL,
		Status:           upOrder.Status,
		Identifiers:      string(idJSON),
		Profile:          req.Profile,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	if err := h.store.SaveOrder(r.Context(), order); err != nil {
		h.writeError(w, errServerInternal("saving order"))
		return
	}

	// ── Map upstream URLs → gateway UUIDs ────────────────────────────────────
	finalizeID := uuid.New().String()
	if err := h.store.SaveResource(r.Context(), &model.ResourceMap{
		GatewayID:    finalizeID,
		ResourceType: model.ResourceTypeFinalize,
		OrderID:      orderID,
		UpstreamURL:  upOrder.Finalize,
	}); err != nil {
		h.writeError(w, errServerInternal("saving finalize resource"))
		return
	}

	gatewayAuthzURLs := make([]string, len(upOrder.Authorizations))
	for i, upAuthzURL := range upOrder.Authorizations {
		authzID := uuid.New().String()
		if err := h.store.SaveResource(r.Context(), &model.ResourceMap{
			GatewayID:    authzID,
			ResourceType: model.ResourceTypeAuthz,
			OrderID:      orderID,
			UpstreamURL:  upAuthzURL,
		}); err != nil {
			h.writeError(w, errServerInternal("saving authz resource"))
			return
		}
		gatewayAuthzURLs[i] = h.cfg.Server.BaseURL + "/authz/" + authzID
	}

	orderURL := h.cfg.Server.BaseURL + "/order/" + orderID
	resp := &orderResponse{
		Status:         upOrder.Status,
		Expires:        upOrder.Expires,
		Identifiers:    req.Identifiers,
		Authorizations: gatewayAuthzURLs,
		Finalize:       h.cfg.Server.BaseURL + "/finalize/" + finalizeID,
	}

	h.log.Info("order created",
		"account_id", acct.ID,
		"order_id", orderID,
		"upstream_id", decision.UpstreamID,
		"routing_signal", routingSignal(req.Profile, acct.KeyType, req.Identifiers),
		"profile", req.Profile,
		"upstream_profile", upstreamProfile,
		"identifiers", idJSON,
		"status", upOrder.Status,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	w.Header().Set("Location", orderURL)
	writeJSON(w, http.StatusCreated, resp)
}

// ─── POST /order/{id} ─────────────────────────────────────────────────────────

func (h *Handler) handleOrder(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	acct, aerr := h.resolveAndVerify(r.Context(), w, parsed)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}

	orderID := chi.URLParam(r, "id")
	order, err := h.store.GetOrder(r.Context(), orderID)
	if err != nil || order == nil {
		h.writeError(w, errNotFound("order not found"))
		return
	}
	if order.AccountID != acct.ID {
		h.writeError(w, errUnauthorized("order does not belong to this account"))
		return
	}

	client, err := h.pool.GetSlot(r.Context(), order.UpstreamID, order.UpstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	upOrder, err := client.GetOrder(r.Context(), order.UpstreamOrderURL)
	if err != nil {
		h.writeError(w, errServerInternal("polling upstream order: "+err.Error()))
		return
	}

	// Update status in the store.
	if upOrder.Status != order.Status {
		h.store.UpdateOrderStatus(r.Context(), orderID, upOrder.Status) //nolint:errcheck,gosec
	}

	resp, aerr := h.buildOrderResponse(r.Context(), orderID, upOrder)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── POST /authz/{id} ─────────────────────────────────────────────────────────

func (h *Handler) handleAuthz(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	acct, aerr := h.resolveAndVerify(r.Context(), w, parsed)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}

	authzID := chi.URLParam(r, "id")
	rm, err := h.store.GetResource(r.Context(), authzID)
	if err != nil || rm == nil {
		h.writeError(w, errNotFound("authorization not found"))
		return
	}

	order, err := h.store.GetOrder(r.Context(), rm.OrderID)
	if err != nil || order == nil {
		h.writeError(w, errNotFound("order for authorization not found"))
		return
	}
	if order.AccountID != acct.ID {
		h.writeError(w, errUnauthorized("authorization does not belong to this account"))
		return
	}

	client, err := h.pool.GetSlot(r.Context(), order.UpstreamID, order.UpstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	upAuthz, err := client.GetAuthorization(r.Context(), rm.UpstreamURL)
	if err != nil {
		h.writeError(w, errServerInternal("fetching authorization: "+err.Error()))
		return
	}

	// Map challenge URLs to gateway UUIDs and rewrite the response.
	rewrittenChallenges := make([]interface{}, len(upAuthz.Challenges))
	for i, chal := range upAuthz.Challenges {
		rm, err := h.store.GetResourceByUpstreamURL(r.Context(), chal.URL)
		if err != nil {
			h.writeError(w, errServerInternal("checking challenge resource"))
			return
		}
		var gatewayID string
		if rm != nil {
			gatewayID = rm.GatewayID
		} else {
			if err := h.store.SaveResource(r.Context(), &model.ResourceMap{
				GatewayID:    uuid.New().String(),
				ResourceType: model.ResourceTypeChallenge,
				OrderID:      order.ID,
				UpstreamURL:  chal.URL,
			}); err != nil {
				h.writeError(w, errServerInternal("saving challenge resource"))
				return
			}
			// Re-read after INSERT OR IGNORE: if two goroutines raced on the same
			// authz URL, the winner's UUID was persisted; always use the stored
			// gateway_id so the returned URL resolves correctly.
			persisted, err := h.store.GetResourceByUpstreamURL(r.Context(), chal.URL)
			if err != nil || persisted == nil {
				h.writeError(w, errServerInternal("reading challenge resource"))
				return
			}
			gatewayID = persisted.GatewayID
		}
		rewrittenChallenges[i] = map[string]interface{}{
			"type":   chal.Type,
			"url":    h.cfg.Server.BaseURL + "/challenge/" + gatewayID,
			"token":  chal.Token,
			"status": chal.Status,
		}
	}

	resp := map[string]interface{}{
		"identifier": upAuthz.Identifier,
		"status":     upAuthz.Status,
		"challenges": rewrittenChallenges,
	}
	if upAuthz.Expires != "" {
		resp["expires"] = upAuthz.Expires
	}
	if upAuthz.Wildcard {
		resp["wildcard"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── POST /challenge/{id} ─────────────────────────────────────────────────────

func (h *Handler) handleChallenge(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	acct, aerr := h.resolveAndVerify(r.Context(), w, parsed)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}

	chalID := chi.URLParam(r, "id")
	rm, err := h.store.GetResource(r.Context(), chalID)
	if err != nil || rm == nil {
		h.writeError(w, errNotFound("challenge not found"))
		return
	}

	order, err := h.store.GetOrder(r.Context(), rm.OrderID)
	if err != nil || order == nil {
		h.writeError(w, errNotFound("order for challenge not found"))
		return
	}
	if order.AccountID != acct.ID {
		h.writeError(w, errUnauthorized("challenge does not belong to this account"))
		return
	}

	client, err := h.pool.GetSlot(r.Context(), order.UpstreamID, order.UpstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	chal, err := client.TriggerChallenge(r.Context(), rm.UpstreamURL)
	if err != nil {
		h.writeError(w, errServerInternal("triggering challenge: "+err.Error()))
		return
	}

	resp := map[string]interface{}{
		"type":   chal.Type,
		"url":    h.cfg.Server.BaseURL + "/challenge/" + chalID,
		"token":  chal.Token,
		"status": chal.Status,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── POST /finalize/{id} ──────────────────────────────────────────────────────

type finalizeRequest struct {
	CSR string `json:"csr"` // base64url-encoded DER
}

func (h *Handler) handleFinalize(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	acct, aerr := h.resolveAndVerify(r.Context(), w, parsed)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}

	finalizeID := chi.URLParam(r, "id")
	rm, err := h.store.GetResource(r.Context(), finalizeID)
	if err != nil || rm == nil {
		h.writeError(w, errNotFound("finalize resource not found"))
		return
	}

	order, err := h.store.GetOrder(r.Context(), rm.OrderID)
	if err != nil || order == nil {
		h.writeError(w, errNotFound("order not found"))
		return
	}
	if order.AccountID != acct.ID {
		h.writeError(w, errUnauthorized("order does not belong to this account"))
		return
	}

	var req finalizeRequest
	if err := json.Unmarshal(parsed.Payload, &req); err != nil {
		h.writeError(w, errMalformed("invalid finalize payload"))
		return
	}
	if req.CSR == "" {
		h.writeError(w, errMalformed("csr is required"))
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		h.writeError(w, errMalformed("invalid csr encoding"))
		return
	}

	csrKeyType, err := csrKeyTypeFromDER(csrDER)
	if err != nil {
		h.writeError(w, errMalformed("invalid csr"))
		return
	}
	if acct.KeyType != "" && csrKeyType != "" && acct.KeyType != csrKeyType {
		h.log.Warn("csr/account key type mismatch",
			"account_id", acct.ID,
			"order_id", order.ID,
			"profile", order.Profile,
			"upstream_id", order.UpstreamID,
			"account_key_type", acct.KeyType,
			"csr_key_type", csrKeyType,
		)
	}

	client, err := h.pool.GetSlot(r.Context(), order.UpstreamID, order.UpstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	upOrder, err := client.FinalizeOrder(r.Context(), rm.UpstreamURL, csrDER)
	if err != nil {
		h.writeError(w, errServerInternal("finalizing upstream order: "+err.Error()))
		return
	}

	h.store.UpdateOrderStatus(r.Context(), order.ID, upOrder.Status) //nolint:errcheck,gosec

	resp, aerr := h.buildOrderResponse(r.Context(), order.ID, upOrder)
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─── GET /cert/{id} ───────────────────────────────────────────────────────────

// handleCert serves GET /cert/{id} and POST /cert/{id} (POST-as-GET per RFC 8555 §7.4.2).
// Both forms return the PEM certificate chain. For POST requests the JWS body is validated
// but the payload is expected to be empty (null), as required by POST-as-GET.
func (h *Handler) handleCert(w http.ResponseWriter, r *http.Request) {
	// POST-as-GET: validate the JWS and consume the nonce, then proceed as GET.
	if r.Method == http.MethodPost {
		h.addCommonHeaders(w)
		parsed, ok := h.parseAndValidateJWS(w, r)
		if !ok {
			return
		}
		if len(parsed.Payload) != 0 {
			h.writeError(w, errMalformed("POST-as-GET payload must be empty"))
			return
		}
		if _, aerr := h.resolveAndVerify(r.Context(), w, parsed); aerr != nil {
			h.writeError(w, aerr)
			return
		}
	}

	certID := chi.URLParam(r, "id")
	rm, err := h.store.GetResource(r.Context(), certID)
	if err != nil || rm == nil {
		h.writeError(w, errNotFound("certificate not found"))
		return
	}

	order, err := h.store.GetOrder(r.Context(), rm.OrderID)
	if err != nil || order == nil {
		h.writeError(w, errNotFound("order not found"))
		return
	}

	client, err := h.pool.GetSlot(r.Context(), order.UpstreamID, order.UpstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	chain, err := client.FetchCertificate(r.Context(), rm.UpstreamURL)
	if err != nil {
		h.writeError(w, errServerInternal("fetching certificate: "+err.Error()))
		return
	}

	// Cache the leaf-cert fingerprint so revocation can be routed to the correct upstream.
	if rm.CertFingerprint == "" {
		if fp, ok := leafCertFingerprint(chain); ok {
			if err := h.store.UpdateResourceCertFingerprint(r.Context(), certID, fp); err != nil {
				h.log.Warn("cert fingerprint cache: failed to write", "certID", certID, "err", err)
			}
		}
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(chain) /* #nosec G705 */ //nolint:errcheck,gosec
}

// ─── POST /revoke-cert ────────────────────────────────────────────────────────

type revokeCertRequest struct {
	Certificate string `json:"certificate"` // base64url DER
	Reason      *int   `json:"reason,omitempty"`
}

func (h *Handler) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)

	parsed, ok := h.parseAndValidateJWS(w, r)
	if !ok {
		return
	}
	// Revoke may use either kid (account) or jwk (key pair directly).
	var acct *model.Account
	if parsed.EmbeddedJWK != nil {
		if err := parsed.VerifySignature(parsed.EmbeddedJWK.Key); err != nil {
			h.writeError(w, errUnauthorized("signature verification failed"))
			return
		}
	} else {
		var aerr *acmeError
		acct, aerr = h.resolveAndVerify(r.Context(), w, parsed)
		if aerr != nil {
			h.writeError(w, aerr)
			return
		}
	}

	var req revokeCertRequest
	if err := json.Unmarshal(parsed.Payload, &req); err != nil {
		h.writeError(w, errMalformed("invalid revoke payload"))
		return
	}
	if req.Certificate == "" {
		h.writeError(w, errMalformed("certificate is required"))
		return
	}

	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		h.writeError(w, errMalformed("invalid certificate encoding"))
		return
	}

	// RFC 8555 §7.6: when using embedded JWK, verify it matches the certificate's subject public key.
	if parsed.EmbeddedJWK != nil {
		cert, cerr := x509.ParseCertificate(certDER)
		if cerr != nil {
			h.writeError(w, errMalformed("invalid certificate DER"))
			return
		}
		if !jwkMatchesCertKey(parsed.EmbeddedJWK, cert) {
			h.writeError(w, errUnauthorized("JWK does not match certificate public key"))
			return
		}
	}

	// Determine which upstream holds this certificate: look up by SHA-256 fingerprint
	// (populated the first time /cert/{id} is fetched) and fall back to default upstream.
	// Note: a cert whose /cert/{id} was never fetched will have a NULL fingerprint and
	// route to the default upstream — acceptable for normal ACME clients, which always
	// fetch the cert before they could revoke it.
	upstreamID := h.cfg.Routing.DefaultUpstream
	upstreamSlot := 0
	fp := hex.EncodeToString(sha256sum(certDER))
	if certRM, err := h.store.GetResourceByCertFingerprint(r.Context(), fp); err == nil && certRM != nil {
		if certOrder, err := h.store.GetOrder(r.Context(), certRM.OrderID); err == nil && certOrder != nil {
			upstreamID = certOrder.UpstreamID
			upstreamSlot = certOrder.UpstreamSlot
			// For KID-based revocation, verify the requesting account owns this cert.
			if acct != nil && certOrder.AccountID != acct.ID {
				h.writeError(w, errUnauthorized("certificate does not belong to this account"))
				return
			}
		}
	} else if acct != nil {
		// Fingerprint not in store (cert was never fetched via /cert/{id}).
		// Local ownership cannot be enforced; the upstream CA is the safety net.
		h.log.Warn("revoke: cert fingerprint not cached, ownership check skipped",
			"account_id", acct.ID,
			"upstream_id", upstreamID,
		)
	}
	reason := -1
	if req.Reason != nil {
		reason = *req.Reason
	}

	client, err := h.pool.GetSlot(r.Context(), upstreamID, upstreamSlot)
	if err != nil {
		h.writeError(w, errServerInternal("upstream unavailable"))
		return
	}

	if err := client.RevokeCertificate(r.Context(), certDER, reason); err != nil {
		h.writeError(w, errServerInternal("revoking certificate: "+err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ─── POST /key-change ────────────────────────────────────────────────────────

// handleKeyChange satisfies the RFC 8555 §7.1.1 requirement that keyChange be
// advertised in the directory. Key roll-over is not implemented in this version.
func (h *Handler) handleKeyChange(w http.ResponseWriter, r *http.Request) {
	h.addCommonHeaders(w)
	h.writeError(w, &acmeError{
		Type:   "urn:ietf:params:acme:error:serverInternal",
		Detail: "key roll-over is not supported by this gateway",
		Status: http.StatusInternalServerError,
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// resolveAndVerify resolves the account from a KID JWS and verifies the signature.
func (h *Handler) resolveAndVerify(ctx context.Context, w http.ResponseWriter, parsed *ParsedJWS) (*model.Account, *acmeError) {
	acct, aerr := h.resolveAccount(ctx, parsed)
	if aerr != nil {
		return nil, aerr
	}

	var pubKey interface{}
	if parsed.EmbeddedJWK != nil {
		pubKey = parsed.EmbeddedJWK.Key
	} else {
		key := h.mustParsePublicKey(acct.PublicKey)
		if key == nil {
			return nil, errServerInternal("could not parse account public key")
		}
		pubKey = key
	}

	if err := parsed.VerifySignature(pubKey); err != nil {
		return nil, errUnauthorized("signature verification failed")
	}
	return acct, nil
}

// mustParsePublicKey parses a JWK JSON string to a crypto.PublicKey. Returns nil on error.
func (h *Handler) mustParsePublicKey(jwkJSON string) interface{} {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return nil
	}
	return jwk.Key
}

// buildOrderResponse constructs a gateway-local order response from an upstream order.
// It maps cert URLs if the order is valid.
func (h *Handler) buildOrderResponse(ctx context.Context, orderID string, upOrder *upstream.ACMEOrder) (*orderResponse, *acmeError) {
	// Retrieve the finalize and cert mappings for this order.
	order, err := h.store.GetOrder(ctx, orderID)
	if err != nil || order == nil {
		return nil, errNotFound("order not found")
	}

	finalizeRM, err := h.store.GetResourceByUpstreamURL(ctx, upOrder.Finalize)
	if err != nil {
		return nil, errServerInternal("looking up finalize resource")
	}

	finalizeURL := ""
	if finalizeRM != nil {
		finalizeURL = h.cfg.Server.BaseURL + "/finalize/" + finalizeRM.GatewayID
	}

	var certURL string
	if upOrder.Certificate != "" {
		rm, _ := h.store.GetResourceByUpstreamURL(ctx, upOrder.Certificate) //nolint:errcheck
		if rm == nil {
			// INSERT OR IGNORE: if two goroutines race on the same order poll,
			// only one UUID wins; re-read to always use the persisted gateway_id.
			h.store.SaveResource(ctx, &model.ResourceMap{ //nolint:errcheck,gosec
				GatewayID:    uuid.New().String(),
				ResourceType: model.ResourceTypeCert,
				OrderID:      orderID,
				UpstreamURL:  upOrder.Certificate,
			})
			rm, _ = h.store.GetResourceByUpstreamURL(ctx, upOrder.Certificate) //nolint:errcheck
		}
		if rm != nil {
			certURL = h.cfg.Server.BaseURL + "/cert/" + rm.GatewayID
		}
	}

	var idList []model.Identifier
	json.Unmarshal([]byte(order.Identifiers), &idList) //nolint:errcheck,gosec

	resp := &orderResponse{
		Status:      upOrder.Status,
		Expires:     upOrder.Expires,
		Identifiers: idList,
		Finalize:    finalizeURL,
		Certificate: certURL,
	}

	// Populate authorizations per RFC 8555 §7.1.3.
	authzRMs, err := h.store.GetAuthzResourcesByOrderID(ctx, orderID)
	if err == nil {
		for _, arm := range authzRMs {
			resp.Authorizations = append(resp.Authorizations, h.cfg.Server.BaseURL+"/authz/"+arm.GatewayID)
		}
	}

	return resp, nil
}

// routingSignal returns a log-friendly string describing which routing signal was used.
func routingSignal(profile, keyType string, ids []model.Identifier) string {
	if profile != "" && keyType != "" {
		return "profile+key_type"
	}
	if profile != "" {
		return "profile"
	}
	if keyType != "" {
		return "key_type"
	}
	for _, id := range ids {
		if strings.Contains(id.Value, ".") {
			return "domain_suffix"
		}
	}
	return "default"
}

// leafCertFingerprint decodes the first PEM block from a PEM chain and returns
// the SHA-256 hex fingerprint of its raw DER bytes (the leaf certificate).
func leafCertFingerprint(pemChain []byte) (string, bool) {
	block, _ := pem.Decode(pemChain)
	if block == nil {
		return "", false
	}
	return hex.EncodeToString(sha256sum(block.Bytes)), true
}

// sha256sum returns the SHA-256 digest of b as a byte slice.
func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// csrKeyTypeFromDER parses a DER CSR and returns the public key algorithm as
// "RSA", "ECDSA", "Ed25519", or "" for unknown types.
func csrKeyTypeFromDER(csrDER []byte) (string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return "", err
	}
	return certRequestKeyType(csr), nil
}

func certRequestKeyType(csr *x509.CertificateRequest) string {
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}

// jwkMatchesCertKey reports whether jwk contains the same public key as cert.
// Used by handleRevokeCert to enforce RFC 8555 §7.6 when revocation uses an embedded JWK.
// Supports ECDSA, RSA, and Ed25519 (RFC 8555 §6.2 SHOULD support EdDSA).
func jwkMatchesCertKey(jwk *jose.JSONWebKey, cert *x509.Certificate) bool {
	switch certKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k, ok := jwk.Key.(*ecdsa.PublicKey); ok {
			return certKey.Equal(k)
		}
	case *rsa.PublicKey:
		if k, ok := jwk.Key.(*rsa.PublicKey); ok {
			return certKey.Equal(k)
		}
	case ed25519.PublicKey:
		if k, ok := jwk.Key.(ed25519.PublicKey); ok {
			return certKey.Equal(k)
		}
	}
	return false
}
