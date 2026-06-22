package server

import (
	"encoding/json"
	"net/http"
)

// directoryResponse is the ACMEv2 directory object (RFC 8555 §7.1.1) including
// the profiles extension (draft-ietf-acme-profiles).
type directoryResponse struct {
	NewNonce   string        `json:"newNonce"`
	NewAccount string        `json:"newAccount"`
	NewOrder   string        `json:"newOrder"`
	RevokeCert string        `json:"revokeCert"`
	KeyChange  string        `json:"keyChange"`
	Meta       directoryMeta `json:"meta"`
}

type directoryMeta struct {
	TermsOfService          string            `json:"termsOfService,omitempty"`
	Website                 string            `json:"website,omitempty"`
	CaaIdentities           []string          `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool              `json:"externalAccountRequired,omitempty"`
	Profiles                map[string]string `json:"profiles,omitempty"`
}

// buildDirectory constructs the directory response object.
func buildDirectory(baseURL string, profiles map[string]string) *directoryResponse {
	return &directoryResponse{
		NewNonce:   baseURL + "/new-nonce",
		NewAccount: baseURL + "/new-account",
		NewOrder:   baseURL + "/new-order",
		RevokeCert: baseURL + "/revoke-cert",
		KeyChange:  baseURL + "/key-change",
		Meta: directoryMeta{
			Website:  baseURL,
			Profiles: profiles,
		},
	}
}

// handleDirectory serves GET /directory.
// RFC 8555 §6.5 requires all responses include Replay-Nonce header.
func (h *Handler) handleDirectory(w http.ResponseWriter, r *http.Request) {
	h.attachNonce(w)
	dir := buildDirectory(h.cfg.Server.BaseURL, h.cfg.Profiles)
	writeJSON(w, http.StatusOK, dir)
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
// Sets Content-Type: application/json.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck,gosec
}
