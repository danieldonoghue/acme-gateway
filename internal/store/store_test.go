package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/model"
	"github.com/danieldonoghue/acme-gateway/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s
}

// saveTestAccount inserts a minimal account row to satisfy FK constraints.
func saveTestAccount(t *testing.T, s *store.Store, id string) {
	t.Helper()
	a := &model.Account{
		ID: id, PublicKey: "pk", KeyType: "ECDSA",
		Status: "valid", CreatedAt: time.Now().UTC(),
	}
	if err := s.SaveAccount(context.Background(), a); err != nil {
		t.Fatalf("saveTestAccount(%q): %v", id, err)
	}
}

// saveTestOrder inserts a minimal order row (and its parent account) to
// satisfy FK constraints for resource_map tests.
func saveTestOrder(t *testing.T, s *store.Store, orderID, accountID string) {
	t.Helper()
	saveTestAccount(t, s, accountID)
	o := &model.Order{
		ID: orderID, AccountID: accountID,
		UpstreamID: "le", UpstreamSlot: 0,
		UpstreamOrderURL: "https://acme.example.com/order/1",
		Status:           "pending", Identifiers: `[{"type":"dns","value":"example.com"}]`,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.SaveOrder(context.Background(), o); err != nil {
		t.Fatalf("saveTestOrder(%q): %v", orderID, err)
	}
}

// ── store lifecycle ───────────────────────────────────────────────────────────

func TestNew_OpenAndClose(t *testing.T) {
	s := newTestStore(t)
	if s == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNew_BadPath(t *testing.T) {
	// A path inside a nonexistent directory cannot be created.
	bad := filepath.Join(t.TempDir(), "no_such_dir", "test.db")
	_, err := store.New(bad)
	if err == nil {
		t.Fatal("expected error for bad DB path")
	}
}

// ── nonces ────────────────────────────────────────────────────────────────────

func TestNonce_IssueAndConsume(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	nonce, err := s.IssueNonce(ctx)
	if err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected non-empty nonce")
	}

	if err := s.ConsumeNonce(ctx, nonce); err != nil {
		t.Fatalf("ConsumeNonce: %v", err)
	}

	// Consuming the same nonce again must fail (replay protection).
	if err := s.ConsumeNonce(ctx, nonce); err == nil {
		t.Fatal("expected error consuming same nonce twice")
	}
}

func TestNonce_ConsumeUnknown(t *testing.T) {
	s := newTestStore(t)
	if err := s.ConsumeNonce(context.Background(), "no-such-nonce"); err == nil {
		t.Fatal("expected error for unknown nonce")
	}
}

func TestNonce_PruneExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.IssueNonce(ctx); err != nil {
		t.Fatalf("IssueNonce: %v", err)
	}
	// Nothing is expired yet; prune should succeed and be a no-op.
	if err := s.PruneExpiredNonces(ctx); err != nil {
		t.Fatalf("PruneExpiredNonces: %v", err)
	}
}

// ── accounts ──────────────────────────────────────────────────────────────────

func TestAccount_SaveAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a := &model.Account{
		ID:        "acct-001",
		PublicKey: `{"kty":"EC","crv":"P-256","x":"abc","y":"def"}`,
		KeyType:   "ECDSA",
		Contact:   []string{"mailto:test@example.com"},
		Status:    "valid",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	got, err := s.GetAccount(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil account")
	}
	if got.ID != a.ID {
		t.Errorf("ID = %q, want %q", got.ID, a.ID)
	}
	if got.Status != a.Status {
		t.Errorf("Status = %q, want %q", got.Status, a.Status)
	}
	if len(got.Contact) != 1 || got.Contact[0] != a.Contact[0] {
		t.Errorf("Contact = %v, want %v", got.Contact, a.Contact)
	}
}

func TestAccount_GetNotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetAccount(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing account")
	}
}

func TestAccount_SaveOverwrite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a := &model.Account{
		ID: "overwrite-me", PublicKey: "pk1", KeyType: "ECDSA",
		Status: "valid", CreatedAt: time.Now().UTC(),
	}
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("first save: %v", err)
	}
	a.Status = "deactivated"
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("second save: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.Status != "deactivated" {
		t.Errorf("status after overwrite = %q, want deactivated", got.Status)
	}
}

// ── upstream accounts ─────────────────────────────────────────────────────────

func TestUpstreamAccount_SaveAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ua := &model.UpstreamAccount{
		UpstreamID: "letsencrypt",
		Slot:       0,
		AccountURL: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
		PrivateKey: "pem-placeholder",
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveUpstreamAccount(ctx, ua); err != nil {
		t.Fatalf("SaveUpstreamAccount: %v", err)
	}

	got, err := s.GetUpstreamAccountBySlot(ctx, ua.UpstreamID, ua.Slot)
	if err != nil {
		t.Fatalf("GetUpstreamAccountBySlot: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil upstream account")
	}
	if got.AccountURL != ua.AccountURL {
		t.Errorf("AccountURL = %q, want %q", got.AccountURL, ua.AccountURL)
	}
	if got.PrivateKey != ua.PrivateKey {
		t.Errorf("PrivateKey = %q, want %q", got.PrivateKey, ua.PrivateKey)
	}
}

func TestUpstreamAccount_MultipleSlots(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for slot := 0; slot < 3; slot++ {
		ua := &model.UpstreamAccount{
			UpstreamID: "le",
			Slot:       slot,
			AccountURL: fmt.Sprintf("https://acme.example.com/acct/%d", slot),
			PrivateKey: fmt.Sprintf("key-%d", slot),
			CreatedAt:  time.Now().UTC(),
		}
		if err := s.SaveUpstreamAccount(ctx, ua); err != nil {
			t.Fatalf("SaveUpstreamAccount slot %d: %v", slot, err)
		}
	}

	for slot := 0; slot < 3; slot++ {
		got, err := s.GetUpstreamAccountBySlot(ctx, "le", slot)
		if err != nil {
			t.Fatalf("GetUpstreamAccountBySlot slot %d: %v", slot, err)
		}
		if got == nil {
			t.Fatalf("slot %d: expected non-nil", slot)
		}
		want := fmt.Sprintf("https://acme.example.com/acct/%d", slot)
		if got.AccountURL != want {
			t.Errorf("slot %d: AccountURL = %q, want %q", slot, got.AccountURL, want)
		}
	}
}

func TestUpstreamAccount_NotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetUpstreamAccountBySlot(context.Background(), "nonexistent", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing upstream account")
	}
}

// ── orders ────────────────────────────────────────────────────────────────────

func TestOrder_SaveGetUpdateStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestAccount(t, s, "acct-abc")

	now := time.Now().UTC().Truncate(time.Second)
	o := &model.Order{
		ID:               "order-001",
		AccountID:        "acct-abc",
		UpstreamID:       "letsencrypt",
		UpstreamSlot:     0,
		UpstreamOrderURL: "https://acme-v02.api.letsencrypt.org/acme/order/1",
		Status:           "pending",
		Identifiers:      `[{"type":"dns","value":"example.com"}]`,
		Profile:          "tlsserver",
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.SaveOrder(ctx, o); err != nil {
		t.Fatalf("SaveOrder: %v", err)
	}

	got, err := s.GetOrder(ctx, o.ID)
	if err != nil {
		t.Fatalf("GetOrder: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil order")
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if got.AccountID != o.AccountID {
		t.Errorf("AccountID = %q, want %q", got.AccountID, o.AccountID)
	}
	if got.UpstreamSlot != o.UpstreamSlot {
		t.Errorf("UpstreamSlot = %d, want %d", got.UpstreamSlot, o.UpstreamSlot)
	}

	if err := s.UpdateOrderStatus(ctx, o.ID, "valid"); err != nil {
		t.Fatalf("UpdateOrderStatus: %v", err)
	}
	got, _ = s.GetOrder(ctx, o.ID)
	if got.Status != "valid" {
		t.Errorf("status after update = %q, want valid", got.Status)
	}
}

func TestOrder_GetNotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetOrder(context.Background(), "no-such-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing order")
	}
}

func TestOrder_UpdateStatusNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpdateOrderStatus(context.Background(), "ghost-order", "valid"); err == nil {
		t.Fatal("expected error updating non-existent order")
	}
}

// ── resources ─────────────────────────────────────────────────────────────────

func TestResource_SaveAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestOrder(t, s, "order-001", "acct-resource-save")

	r := &model.ResourceMap{
		GatewayID:    "gw-authz-001",
		ResourceType: model.ResourceTypeAuthz,
		OrderID:      "order-001",
		UpstreamURL:  "https://acme.example.com/authz/1",
	}
	if err := s.SaveResource(ctx, r); err != nil {
		t.Fatalf("SaveResource: %v", err)
	}

	got, err := s.GetResource(ctx, r.GatewayID)
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil resource")
	}
	if got.UpstreamURL != r.UpstreamURL {
		t.Errorf("UpstreamURL = %q, want %q", got.UpstreamURL, r.UpstreamURL)
	}
	if got.ResourceType != r.ResourceType {
		t.Errorf("ResourceType = %q, want %q", got.ResourceType, r.ResourceType)
	}
}

func TestResource_GetNotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetResource(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing resource")
	}
}

func TestResource_GetByUpstreamURL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestOrder(t, s, "order-byurl", "acct-resource-byurl")

	r := &model.ResourceMap{
		GatewayID:    "gw-chall-001",
		ResourceType: model.ResourceTypeChallenge,
		OrderID:      "order-byurl",
		UpstreamURL:  "https://acme.example.com/chall/xyz",
	}
	if err := s.SaveResource(ctx, r); err != nil {
		t.Fatalf("SaveResource: %v", err)
	}

	got, err := s.GetResourceByUpstreamURL(ctx, r.UpstreamURL)
	if err != nil {
		t.Fatalf("GetResourceByUpstreamURL: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil resource")
	}
	if got.GatewayID != r.GatewayID {
		t.Errorf("GatewayID = %q, want %q", got.GatewayID, r.GatewayID)
	}
}

func TestResource_GetByUpstreamURL_NotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetResourceByUpstreamURL(context.Background(), "https://no-such.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestResource_CertFingerprint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestOrder(t, s, "order-cert", "acct-resource-cert")

	r := &model.ResourceMap{
		GatewayID:    "gw-cert-001",
		ResourceType: model.ResourceTypeCert,
		OrderID:      "order-cert",
		UpstreamURL:  "https://acme.example.com/cert/1",
	}
	if err := s.SaveResource(ctx, r); err != nil {
		t.Fatalf("SaveResource: %v", err)
	}

	const fp = "aabbccddeeff001122"
	if err := s.UpdateResourceCertFingerprint(ctx, r.GatewayID, fp); err != nil {
		t.Fatalf("UpdateResourceCertFingerprint: %v", err)
	}

	got, err := s.GetResourceByCertFingerprint(ctx, fp)
	if err != nil {
		t.Fatalf("GetResourceByCertFingerprint: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil resource")
	}
	if got.CertFingerprint != fp {
		t.Errorf("CertFingerprint = %q, want %q", got.CertFingerprint, fp)
	}
	if got.GatewayID != r.GatewayID {
		t.Errorf("GatewayID = %q, want %q", got.GatewayID, r.GatewayID)
	}
}

func TestResource_GetByCertFingerprint_NotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetResourceByCertFingerprint(context.Background(), "no-such-fp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestResource_GetAuthzByOrderID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestOrder(t, s, "order-multi-authz", "acct-resource-multi")

	const orderID = "order-multi-authz"
	for i := 0; i < 3; i++ {
		r := &model.ResourceMap{
			GatewayID:    fmt.Sprintf("gw-authz-%d", i),
			ResourceType: model.ResourceTypeAuthz,
			OrderID:      orderID,
			UpstreamURL:  fmt.Sprintf("https://acme.example.com/authz/%d", i),
		}
		if err := s.SaveResource(ctx, r); err != nil {
			t.Fatalf("SaveResource[%d]: %v", i, err)
		}
	}
	// Non-authz resource for the same order — must not appear in results.
	other := &model.ResourceMap{
		GatewayID:    "gw-finalize",
		ResourceType: model.ResourceTypeFinalize,
		OrderID:      orderID,
		UpstreamURL:  "https://acme.example.com/finalize/1",
	}
	if err := s.SaveResource(ctx, other); err != nil {
		t.Fatalf("SaveResource other: %v", err)
	}

	got, err := s.GetAuthzResourcesByOrderID(ctx, orderID)
	if err != nil {
		t.Fatalf("GetAuthzResourcesByOrderID: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("got %d authz resources, want 3", len(got))
	}
}

func TestResource_SaveIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	saveTestOrder(t, s, "order-idem", "acct-resource-idem")

	r := &model.ResourceMap{
		GatewayID:    "gw-idem",
		ResourceType: model.ResourceTypeAuthz,
		OrderID:      "order-idem",
		UpstreamURL:  "https://acme.example.com/authz/original",
	}
	if err := s.SaveResource(ctx, r); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// Second save with same GatewayID is INSERT OR IGNORE — must be a no-op.
	r2 := *r
	r2.UpstreamURL = "https://acme.example.com/authz/should-not-overwrite"
	if err := s.SaveResource(ctx, &r2); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, _ := s.GetResource(ctx, r.GatewayID)
	if got.UpstreamURL != r.UpstreamURL {
		t.Errorf("idempotency broken: URL = %q, want %q", got.UpstreamURL, r.UpstreamURL)
	}
}

// ── account-bound upstream accounts ───────────────────────────────────────────

func TestUpstreamAccountForAccount_SaveAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ua := &model.UpstreamAccount{
		UpstreamID: "letsencrypt",
		AccountID:  "acct-001",
		AccountURL: "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
		PrivateKey: "pem-placeholder",
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if err := s.SaveUpstreamAccountForAccount(ctx, ua); err != nil {
		t.Fatalf("SaveUpstreamAccountForAccount: %v", err)
	}

	got, err := s.GetUpstreamAccountForAccount(ctx, ua.UpstreamID, ua.AccountID)
	if err != nil {
		t.Fatalf("GetUpstreamAccountForAccount: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil upstream account")
	}
	if got.AccountURL != ua.AccountURL {
		t.Errorf("AccountURL = %q, want %q", got.AccountURL, ua.AccountURL)
	}
	if got.PrivateKey != ua.PrivateKey {
		t.Errorf("PrivateKey = %q, want %q", got.PrivateKey, ua.PrivateKey)
	}
	if got.AccountID != ua.AccountID {
		t.Errorf("AccountID = %q, want %q", got.AccountID, ua.AccountID)
	}
}

func TestUpstreamAccountForAccount_GetNotFound(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetUpstreamAccountForAccount(context.Background(), "letsencrypt", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing upstream account")
	}
}

func TestUpstreamAccountForAccount_MultipleAccounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Save upstream accounts for different gateway accounts
	for i := 0; i < 3; i++ {
		accountID := fmt.Sprintf("acct-%03d", i)
		ua := &model.UpstreamAccount{
			UpstreamID: "le",
			AccountID:  accountID,
			AccountURL: fmt.Sprintf("https://acme.example.com/acct/%d", i),
			PrivateKey: fmt.Sprintf("key-%d", i),
			CreatedAt:  time.Now().UTC(),
		}
		if err := s.SaveUpstreamAccountForAccount(ctx, ua); err != nil {
			t.Fatalf("SaveUpstreamAccountForAccount[%d]: %v", i, err)
		}
	}

	// Verify each can be retrieved independently
	for i := 0; i < 3; i++ {
		accountID := fmt.Sprintf("acct-%03d", i)
		got, err := s.GetUpstreamAccountForAccount(ctx, "le", accountID)
		if err != nil {
			t.Fatalf("GetUpstreamAccountForAccount[%d]: %v", i, err)
		}
		if got == nil {
			t.Fatalf("account %d: expected non-nil", i)
		}
		want := fmt.Sprintf("https://acme.example.com/acct/%d", i)
		if got.AccountURL != want {
			t.Errorf("account %d: AccountURL = %q, want %q", i, got.AccountURL, want)
		}
	}
}

func TestUpstreamAccountForAccount_Overwrite(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ua := &model.UpstreamAccount{
		UpstreamID: "le",
		AccountID:  "acct-shared",
		AccountURL: "https://acme.example.com/acct/original",
		PrivateKey: "original-key",
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.SaveUpstreamAccountForAccount(ctx, ua); err != nil {
		t.Fatalf("first save: %v", err)
	}

	// Update the same (upstream_id, account_id) pair
	ua.AccountURL = "https://acme.example.com/acct/updated"
	ua.PrivateKey = "updated-key"
	if err := s.SaveUpstreamAccountForAccount(ctx, ua); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, _ := s.GetUpstreamAccountForAccount(ctx, ua.UpstreamID, ua.AccountID)
	if got.AccountURL != "https://acme.example.com/acct/updated" {
		t.Errorf("AccountURL = %q, want updated", got.AccountURL)
	}
	if got.PrivateKey != "updated-key" {
		t.Errorf("PrivateKey = %q, want updated", got.PrivateKey)
	}
}
