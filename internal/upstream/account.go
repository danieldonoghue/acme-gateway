package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"

	"github.com/danieldonoghue/acme-gateway/internal/config"
)

// Register creates or retrieves the gateway's account at the upstream CA.
// If the account already exists (determined by the directory's newAccount endpoint
// returning 200), the existing account URL is returned.
//
// eabCfg may be nil for CAs that do not require External Account Binding.
func (c *Client) Register(ctx context.Context, contactEmail string, eabCfg *config.EABConfig) (accountURL string, err error) {
	dir, err := c.Directory(ctx)
	if err != nil {
		return "", err
	}

	accountPayload := map[string]interface{}{
		"contact":              []string{"mailto:" + contactEmail},
		"termsOfServiceAgreed": true,
	}

	if eabCfg != nil {
		eab, err := c.buildEAB(dir.NewAccount, eabCfg)
		if err != nil {
			return "", fmt.Errorf("building EAB: %w", err)
		}
		accountPayload["externalAccountBinding"] = eab
	}

	resp, err := c.signedPost(ctx, dir.NewAccount, accountPayload)
	if err != nil {
		return "", fmt.Errorf("posting new-account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", parseACMEError(resp)
	}

	accountURL = resp.Header.Get("Location")
	if accountURL == "" {
		// Some CAs return the account URL in the response body.
		var body map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
			if u, ok := body["id"].(string); ok {
				accountURL = u
			}
		}
	}
	if accountURL == "" {
		return "", fmt.Errorf("upstream did not return account URL")
	}
	c.SetAccountURL(accountURL)
	return accountURL, nil
}

// buildEAB constructs the External Account Binding JWS as required by RFC 8555 §7.3.4.
// The EAB JWS payload is the gateway's public JWK; the EAB JWS is signed with
// the HMAC key provided by the CA operator.
func (c *Client) buildEAB(newAccountURL string, eabCfg *config.EABConfig) (json.RawMessage, error) {
	// Decode the base64url-encoded HMAC key.
	hmacKey, err := base64.RawURLEncoding.DecodeString(eabCfg.HMACKey)
	if err != nil {
		// Some CAs encode the HMAC key with standard base64 padding.
		hmacKey, err = base64.StdEncoding.DecodeString(eabCfg.HMACKey)
		if err != nil {
			return nil, fmt.Errorf("decoding EAB HMAC key: %w", err)
		}
	}

	// The payload of the EAB JWS is the account public key JWK.
	pubJWK := jose.JSONWebKey{Key: c.key.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	pubJWKBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, err
	}

	sigKey := jose.SigningKey{Algorithm: jose.HS256, Key: hmacKey}
	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderKey("kid"), eabCfg.KeyID)
	opts.WithHeader(jose.HeaderKey("url"), newAccountURL)

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		return nil, fmt.Errorf("creating EAB signer: %w", err)
	}

	jws, err := signer.Sign(pubJWKBytes)
	if err != nil {
		return nil, fmt.Errorf("signing EAB: %w", err)
	}

	return json.RawMessage(jws.FullSerialize()), nil
}
