// Package router evaluates routing rules to select an upstream CA and
// determine the upstream profile behaviour for a given ACME order request.
package router

import (
	"strings"

	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/model"
)

// Decision is the result of routing an order request.
type Decision struct {
	// UpstreamID is the key from config.Upstreams that should serve this order.
	UpstreamID string

	// UpstreamProfile controls what profile field is sent to the upstream CA:
	//   ""             → strip (omit the field) — DEFAULT
	//   "$passthrough" → forward the inbound profile verbatim
	//   any other string → override with this exact value
	UpstreamProfile string

	// RequireCSRKeyType, when non-empty ("RSA" or "ECDSA"), means the CSR
	// submitted at finalize must use a key of this type; a mismatch is
	// rejected with an ACME badCSR error before contacting the upstream.
	RequireCSRKeyType string
}

// Request contains the information available at routing time.
type Request struct {
	// Profile is the profile name from the ACME newOrder payload (may be empty).
	Profile string

	// KeyType is the account's key type: "RSA" or "ECDSA" (may be empty if unknown).
	KeyType string

	// Identifiers are the requested DNS names / IP addresses in the order.
	Identifiers []model.Identifier
}

// Router evaluates the configured routing rules.
type Router struct {
	cfg *config.RoutingConfig
}

// New creates a Router from the routing section of the config.
func New(cfg *config.RoutingConfig) *Router {
	return &Router{cfg: cfg}
}

// Route evaluates rules in order; the first match wins.
// Falls back to default_upstream if no rule matches.
// Returns ("", Decision{}) with a nil error if no rule matches and no default is set
// (callers should treat this as an error).
func (r *Router) Route(req *Request) Decision {
	for _, rule := range r.cfg.Rules {
		if matches(rule.Match, req) {
			return Decision{
				UpstreamID:        rule.Upstream,
				UpstreamProfile:   rule.UpstreamProfile,
				RequireCSRKeyType: rule.RequireCSRKeyType,
			}
		}
	}
	return Decision{UpstreamID: r.cfg.DefaultUpstream}
}

// ResolveUpstreamProfile computes the actual profile string to send upstream
// given a routing Decision and the inbound profile from the client.
//
// Behaviour:
//   - UpstreamProfile == ""             → strip; return ""
//   - UpstreamProfile == "$passthrough" → return inboundProfile as-is
//   - otherwise                         → return UpstreamProfile (override)
func ResolveUpstreamProfile(d Decision, inboundProfile string) string {
	switch d.UpstreamProfile {
	case "":
		return ""
	case model.UpstreamProfilePassthrough:
		return inboundProfile
	default:
		return d.UpstreamProfile
	}
}

// matches returns true if all non-empty fields in mc match the request.
func matches(mc config.MatchConfig, req *Request) bool {
	if mc.Profile != "" && mc.Profile != req.Profile {
		return false
	}
	if mc.KeyType != "" && !strings.EqualFold(mc.KeyType, req.KeyType) {
		return false
	}
	if mc.DomainSuffix != "" && !anyIdentifierHasSuffix(req.Identifiers, mc.DomainSuffix) {
		return false
	}
	// A rule with all-empty match fields is a catch-all that always matches.
	return true
}

func anyIdentifierHasSuffix(ids []model.Identifier, suffix string) bool {
	for _, id := range ids {
		if strings.HasSuffix(id.Value, suffix) {
			return true
		}
	}
	return false
}
