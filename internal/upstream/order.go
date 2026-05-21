package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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
func (c *Client) FetchCertificate(ctx context.Context, certURL string) ([]byte, error) {
	resp, err := c.signedPost(ctx, certURL, nil) // nil = POST-as-GET
	if err != nil {
		return nil, fmt.Errorf("fetching certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseACMEError(resp)
	}

	return io.ReadAll(resp.Body)
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
