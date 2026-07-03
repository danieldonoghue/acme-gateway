package router

import (
	"testing"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
)

func makeRouter(rules []config.RoutingRule, defaultUpstream string) *Router {
	return New(&config.RoutingConfig{
		Rules:           rules,
		DefaultUpstream: defaultUpstream,
	})
}

// ─── Route matching ───────────────────────────────────────────────────────────

func TestRoute_ProfileMatch(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{Profile: "tlsserver"}, Upstream: "letsencrypt"},
		{Match: config.MatchConfig{Profile: "tlsclient"}, Upstream: "private-ca"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "tlsclient", KeyType: "RSA"})
	if d.UpstreamID != "private-ca" {
		t.Errorf("upstream = %q, want private-ca", d.UpstreamID)
	}
}

func TestRoute_ProfileAndKeyType(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{Profile: "tlsclient", KeyType: "RSA"}, Upstream: "private-ca-rsa"},
		{Match: config.MatchConfig{Profile: "tlsclient", KeyType: "ECDSA"}, Upstream: "private-ca-ecdsa"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "tlsclient", KeyType: "ECDSA"})
	if d.UpstreamID != "private-ca-ecdsa" {
		t.Errorf("upstream = %q, want private-ca-ecdsa", d.UpstreamID)
	}
}

func TestRoute_RequireCSRKeyTypeCarried(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{Profile: "tlsclient-rsa"}, Upstream: "private-ca-rsa", RequireCSRKeyType: "RSA"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "tlsclient-rsa"})
	if d.RequireCSRKeyType != "RSA" {
		t.Errorf("RequireCSRKeyType = %q, want RSA", d.RequireCSRKeyType)
	}

	// Default (no rule match) carries no requirement.
	d = r.Route(&Request{Profile: "other"})
	if d.RequireCSRKeyType != "" {
		t.Errorf("RequireCSRKeyType = %q, want empty for default upstream", d.RequireCSRKeyType)
	}
}

func TestRoute_KeyTypeCaseInsensitive(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{KeyType: "RSA"}, Upstream: "private-ca-rsa"},
	}, "letsencrypt")

	d := r.Route(&Request{KeyType: "rsa"})
	if d.UpstreamID != "private-ca-rsa" {
		t.Errorf("upstream = %q, want private-ca-rsa", d.UpstreamID)
	}
}

func TestRoute_DomainSuffix(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{DomainSuffix: ".internal"}, Upstream: "private-ca-rsa"},
	}, "letsencrypt")

	d := r.Route(&Request{
		Identifiers: []model.Identifier{{Type: "dns", Value: "myhost.internal"}},
	})
	if d.UpstreamID != "private-ca-rsa" {
		t.Errorf("upstream = %q, want private-ca-rsa", d.UpstreamID)
	}
}

func TestRoute_DomainSuffixNoMatch(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{DomainSuffix: ".internal"}, Upstream: "private-ca-rsa"},
	}, "letsencrypt")

	d := r.Route(&Request{
		Identifiers: []model.Identifier{{Type: "dns", Value: "myhost.example.com"}},
	})
	if d.UpstreamID != "letsencrypt" {
		t.Errorf("upstream = %q, want letsencrypt (default)", d.UpstreamID)
	}
}

func TestRoute_FirstMatchWins(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{Profile: "tlsserver"}, Upstream: "first"},
		{Match: config.MatchConfig{Profile: "tlsserver"}, Upstream: "second"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "tlsserver"})
	if d.UpstreamID != "first" {
		t.Errorf("upstream = %q, want first", d.UpstreamID)
	}
}

func TestRoute_Default(t *testing.T) {
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{Profile: "tlsclient"}, Upstream: "private-ca"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "other"})
	if d.UpstreamID != "letsencrypt" {
		t.Errorf("upstream = %q, want letsencrypt (default)", d.UpstreamID)
	}
}

func TestRoute_CatchAllRule(t *testing.T) {
	// A rule with no match conditions is a catch-all.
	r := makeRouter([]config.RoutingRule{
		{Match: config.MatchConfig{}, Upstream: "catchall"},
	}, "letsencrypt")

	d := r.Route(&Request{Profile: "anything", KeyType: "RSA"})
	if d.UpstreamID != "catchall" {
		t.Errorf("upstream = %q, want catchall", d.UpstreamID)
	}
}

// ─── Upstream profile resolution ──────────────────────────────────────────────

func TestResolveUpstreamProfile_Strip(t *testing.T) {
	d := Decision{UpstreamID: "le", UpstreamProfile: ""}
	got := ResolveUpstreamProfile(d, "tlsserver")
	if got != "" {
		t.Errorf("expected empty string (strip), got %q", got)
	}
}

func TestResolveUpstreamProfile_Override(t *testing.T) {
	d := Decision{UpstreamID: "le", UpstreamProfile: "tlsserver"}
	got := ResolveUpstreamProfile(d, "anything")
	if got != "tlsserver" {
		t.Errorf("expected override %q, got %q", "tlsserver", got)
	}
}

func TestResolveUpstreamProfile_Passthrough(t *testing.T) {
	d := Decision{UpstreamID: "internal-ca", UpstreamProfile: "$passthrough"}
	got := ResolveUpstreamProfile(d, "custom-internal-profile")
	if got != "custom-internal-profile" {
		t.Errorf("expected passthrough %q, got %q", "custom-internal-profile", got)
	}
}

func TestResolveUpstreamProfile_PassthroughEmpty(t *testing.T) {
	// Passthrough with no inbound profile passes empty string.
	d := Decision{UpstreamID: "internal-ca", UpstreamProfile: "$passthrough"}
	got := ResolveUpstreamProfile(d, "")
	if got != "" {
		t.Errorf("expected empty passthrough, got %q", got)
	}
}
