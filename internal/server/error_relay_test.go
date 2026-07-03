package server

import (
	"errors"
	"net/http"
	"testing"

	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

func TestRelayUpstreamError_RelaysACMEProblemAndSubproblems(t *testing.T) {
	t.Parallel()

	sub := `[{"type":"urn:ietf:params:acme:error:badCSR","detail":"bad SAN","identifier":{"type":"dns","value":"a.example"}}]`
	src := &upstream.ACMEError{
		Type:        "urn:ietf:params:acme:error:badCSR",
		Detail:      "CSR rejected",
		Status:      http.StatusBadRequest,
		Subproblems: []byte(sub),
	}

	got := relayUpstreamError("finalizing upstream order", src)

	if got.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", got.Status)
	}
	if got.Type != src.Type {
		t.Errorf("type = %q, want %q", got.Type, src.Type)
	}
	if got.Detail != src.Detail {
		t.Errorf("detail = %q, want %q", got.Detail, src.Detail)
	}
	if string(got.Subproblems) != sub {
		t.Errorf("subproblems = %q, want %q", string(got.Subproblems), sub)
	}
}

func TestRelayUpstreamError_MissingStatusBecomesBadGateway(t *testing.T) {
	t.Parallel()

	got := relayUpstreamError("x", &upstream.ACMEError{Type: "urn:ietf:params:acme:error:serverInternal", Detail: "boom"})
	if got.Status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", got.Status)
	}
}

func TestRelayUpstreamError_TransportErrorIsServerInternal(t *testing.T) {
	t.Parallel()

	got := relayUpstreamError("polling upstream order", errors.New("dial tcp: timeout"))
	if got.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", got.Status)
	}
	if got.Type != "urn:ietf:params:acme:error:serverInternal" {
		t.Errorf("type = %q, want serverInternal", got.Type)
	}
}
