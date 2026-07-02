package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CertificateFetchResult contains the fetched PEM chain and any alternate
// certificate URLs advertised by the upstream in Link headers.
type CertificateFetchResult struct {
	Chain             []byte
	AlternateCertURLs []string
}

// NewOrderRequest is the payload for POST /newOrder.
type NewOrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	Profile     string       `json:"profile,omitempty"`
}

// SubmitOrder submits a new order to the upstream CA.
// upstreamProfile is the resolved upstream profile name (empty = omit the field).
func (c *Client) SubmitOrder(ctx context.Context, identifiers []Identifier, upstreamProfile string) (*ACMEOrder, string, error) {
	dir, err := c.Directory(ctx)
	if err != nil {
		return nil, "", err
	}

	payload := map[string]interface{}{
		"identifiers": identifiers,
	}
	if upstreamProfile != "" {
		payload["profile"] = upstreamProfile
	}

	resp, err := c.signedPost(ctx, dir.NewOrder, payload)
	if err != nil {
		return nil, "", fmt.Errorf("submitting order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, "", parseACMEError(resp)
	}

	orderURL := resp.Header.Get("Location")

	var order ACMEOrder
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, "", fmt.Errorf("decoding order response: %w", err)
	}
	return &order, orderURL, nil
}

// GetOrder fetches the current state of an upstream order (POST-as-GET).
func (c *Client) GetOrder(ctx context.Context, orderURL string) (*ACMEOrder, error) {
	resp, err := c.signedPost(ctx, orderURL, nil) // nil = POST-as-GET
	if err != nil {
		return nil, fmt.Errorf("getting order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	var order ACMEOrder
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, fmt.Errorf("decoding order: %w", err)
	}
	return &order, nil
}

// GetAuthorization fetches an authorization object from the upstream (POST-as-GET).
func (c *Client) GetAuthorization(ctx context.Context, authzURL string) (*ACMEAuthorization, error) {
	resp, err := c.signedPost(ctx, authzURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getting authorization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	var authz ACMEAuthorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, fmt.Errorf("decoding authorization: %w", err)
	}
	return &authz, nil
}

// TriggerChallenge sends the challenge-ready notification to the upstream CA.
func (c *Client) TriggerChallenge(ctx context.Context, challengeURL string) (*Challenge, error) {
	resp, err := c.signedPost(ctx, challengeURL, map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("triggering challenge: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	var chal Challenge
	if err := json.NewDecoder(resp.Body).Decode(&chal); err != nil {
		return nil, fmt.Errorf("decoding challenge: %w", err)
	}
	return &chal, nil
}

// FinalizeOrder submits a DER-encoded CSR to the upstream finalize URL.
// It returns the updated order object; the caller is responsible for polling
// until the order reaches "valid" status.
func (c *Client) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) (*ACMEOrder, error) {
	payload := map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	}

	resp, err := c.signedPost(ctx, finalizeURL, payload)
	if err != nil {
		return nil, fmt.Errorf("finalizing order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	var order ACMEOrder
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, fmt.Errorf("decoding finalize response: %w", err)
	}
	return &order, nil
}

// FetchCertificate downloads the PEM certificate chain from the upstream cert URL.
// RFC 8555 §7.4.2: certificate download uses POST-as-GET (nil payload).
// The Accept header requests PEM format; some CAs serve multiple representations.
func (c *Client) FetchCertificate(ctx context.Context, certURL string) ([]byte, error) {
	result, err := c.FetchCertificateWithAlternates(ctx, certURL)
	if err != nil {
		return nil, err
	}
	return result.Chain, nil
}

// FetchCertificateWithAlternates downloads the PEM certificate chain and parses
// Link rel="alternate" headers into absolute certificate URLs.
func (c *Client) FetchCertificateWithAlternates(ctx context.Context, certURL string) (*CertificateFetchResult, error) {
	resp, err := c.signedPostWithHeaders(ctx, certURL, nil, map[string]string{
		"Accept": "application/pem-certificate-chain",
	})
	if err != nil {
		return nil, fmt.Errorf("fetching certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	chain, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	linkBaseURL := certURL
	if resp.Request != nil && resp.Request.URL != nil {
		linkBaseURL = resp.Request.URL.String()
	}

	return &CertificateFetchResult{
		Chain:             chain,
		AlternateCertURLs: parseAlternateCertLinks(resp.Header.Values("Link"), linkBaseURL),
	}, nil
}

// parseAlternateCertLinks extracts Link rel="alternate" targets from raw Link
// header values and resolves them against baseURL.
func parseAlternateCertLinks(linkHeaders []string, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil
	}
	if base.Host == "" {
		return nil
	}

	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, raw := range linkHeaders {
		for _, part := range splitLinkHeaderValues(raw) {
			target, ok := parseAlternateLinkPart(part)
			if !ok {
				continue
			}
			u, err := url.Parse(target)
			if err != nil {
				continue
			}
			resolved := base.ResolveReference(u)
			if resolved.Scheme != "http" && resolved.Scheme != "https" {
				continue
			}
			// Only allow same-origin alternates to avoid expanding outbound fetch
			// targets based on untrusted Link headers.
			if !strings.EqualFold(resolved.Scheme, base.Scheme) || !strings.EqualFold(resolved.Host, base.Host) {
				continue
			}
			s := resolved.String()
			if _, exists := seen[s]; exists {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// splitLinkHeaderValues splits a Link header value into link-value components,
// preserving commas inside quoted strings.
func splitLinkHeaderValues(v string) []string {
	parts := make([]string, 0)
	start := 0
	inQuote := false
	escaped := false
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			if inQuote {
				escaped = !escaped
				continue
			}
			escaped = false
		case '"':
			if !escaped {
				inQuote = !inQuote
			}
			escaped = false
		case ',':
			escaped = false
			if inQuote {
				continue
			}
			parts = append(parts, strings.TrimSpace(v[start:i]))
			start = i + 1
		default:
			escaped = false
		}
	}
	parts = append(parts, strings.TrimSpace(v[start:]))
	return parts
}

// parseAlternateLinkPart returns the target URL from a single link-value when
// it contains rel="alternate" (or rel=alternate).
func parseAlternateLinkPart(part string) (string, bool) {
	part = strings.TrimSpace(part)
	if part == "" || !strings.HasPrefix(part, "<") {
		return "", false
	}
	closeIdx := strings.IndexByte(part, '>')
	if closeIdx <= 1 {
		return "", false
	}
	target := part[1:closeIdx]

	params := strings.Split(part[closeIdx+1:], ";")
	for _, p := range params {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "rel") {
			continue
		}
		relVal := strings.TrimSpace(kv[1])
		relVal = strings.Trim(relVal, "\"")
		for _, rel := range strings.Fields(relVal) {
			if strings.EqualFold(rel, "alternate") {
				return target, true
			}
		}
	}
	return "", false
}

// RevokeCertificate requests revocation of a DER-encoded certificate.
func (c *Client) RevokeCertificate(ctx context.Context, certDER []byte, reason int) error {
	dir, err := c.Directory(ctx)
	if err != nil {
		return err
	}

	payload := map[string]interface{}{
		"certificate": base64.RawURLEncoding.EncodeToString(certDER),
	}
	if reason >= 0 {
		payload["reason"] = reason
	}

	resp, err := c.signedPost(ctx, dir.RevokeCert, payload)
	if err != nil {
		return fmt.Errorf("revoking certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return parseACMEError(resp)
	}
	return nil
}
