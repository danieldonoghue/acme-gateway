package model

import "time"

// Account represents an ACME client account registered with the gateway.
type Account struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"publicKey"` // JWK JSON
	KeyType   string    `json:"keyType"`   // "RSA" | "ECDSA"
	Contact   []string  `json:"contact,omitempty"`
	Status    string    `json:"status"` // "valid" | "deactivated"
	CreatedAt time.Time `json:"createdAt"`
}

// UpstreamAccount represents the gateway's own account at an upstream CA.
type UpstreamAccount struct {
	UpstreamID string    `json:"upstreamId"`
	Slot       int       `json:"slot"` // 0-based index within the upstream's account pool
	AccountURL string    `json:"accountUrl"`
	PrivateKey string    `json:"privateKey"` // PEM-encoded ECDSA key
	CreatedAt  time.Time `json:"createdAt"`
}

// Order represents an ACME order tracked by the gateway.
type Order struct {
	ID               string    `json:"id"`
	AccountID        string    `json:"accountId"`
	UpstreamID       string    `json:"upstreamId"`
	UpstreamSlot     int       `json:"upstreamSlot"` // which account slot within UpstreamID was used
	UpstreamOrderURL string    `json:"upstreamOrderUrl"`
	Status           string    `json:"status"`            // pending/ready/processing/valid/invalid
	Identifiers      string    `json:"identifiers"`       // JSON array
	Profile          string    `json:"profile,omitempty"` // gateway profile name from newOrder
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// ResourceMap maps a gateway-local UUID to an upstream URL.
type ResourceMap struct {
	GatewayID       string `json:"gatewayId"`
	ResourceType    string `json:"resourceType"` // "authz" | "challenge" | "finalize" | "cert"
	OrderID         string `json:"orderId"`
	UpstreamURL     string `json:"upstreamUrl"`
	CertFingerprint string `json:"certFingerprint,omitempty"` // SHA-256 hex of leaf cert DER, populated lazily
}

// Nonce is a single-use replay-protection token.
type Nonce struct {
	Value     string
	ExpiresAt time.Time
}

// Identifier is an ACME identifier (type + value).
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Key type constants.
const (
	KeyTypeRSA   = "RSA"
	KeyTypeECDSA = "ECDSA"
)

// Order status constants.
const (
	OrderStatusPending    = "pending"
	OrderStatusReady      = "ready"
	OrderStatusProcessing = "processing"
	OrderStatusValid      = "valid"
	OrderStatusInvalid    = "invalid"
)

// Account status constants.
const (
	AccountStatusValid       = "valid"
	AccountStatusDeactivated = "deactivated"
)

// Resource type constants.
const (
	ResourceTypeAuthz     = "authz"
	ResourceTypeChallenge = "challenge"
	ResourceTypeFinalize  = "finalize"
	ResourceTypeCert      = "cert"
)

// UpstreamProfilePassthrough is the sentinel value requesting passthrough of the
// inbound profile name to the upstream CA verbatim.
const UpstreamProfilePassthrough = "$passthrough"
