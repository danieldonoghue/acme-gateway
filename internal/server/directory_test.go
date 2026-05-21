package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildDirectory(t *testing.T) {
	profiles := map[string]string{
		"tlsserver": "https://example.com/profiles/tlsserver",
	}
	dir := buildDirectory("https://acme-gw.example.com", profiles)

	if dir.NewNonce != "https://acme-gw.example.com/new-nonce" {
		t.Errorf("NewNonce = %q", dir.NewNonce)
	}
	if dir.NewAccount != "https://acme-gw.example.com/new-account" {
		t.Errorf("NewAccount = %q", dir.NewAccount)
	}
	if dir.NewOrder != "https://acme-gw.example.com/new-order" {
		t.Errorf("NewOrder = %q", dir.NewOrder)
	}
	if dir.RevokeCert != "https://acme-gw.example.com/revoke-cert" {
		t.Errorf("RevokeCert = %q", dir.RevokeCert)
	}
	if dir.KeyChange != "https://acme-gw.example.com/key-change" {
		t.Errorf("KeyChange = %q", dir.KeyChange)
	}
	if dir.Meta.Website != "https://acme-gw.example.com" {
		t.Errorf("Meta.Website = %q", dir.Meta.Website)
	}
	if len(dir.Meta.Profiles) != 1 || dir.Meta.Profiles["tlsserver"] == "" {
		t.Errorf("Meta.Profiles = %v", dir.Meta.Profiles)
	}
}

func TestBuildDirectory_NoProfiles(t *testing.T) {
	dir := buildDirectory("https://gw.example.com", nil)
	if dir.Meta.Profiles != nil {
		t.Errorf("expected nil profiles map, got %v", dir.Meta.Profiles)
	}
}

func TestWriteJSON_StatusAndBody(t *testing.T) {
	type payload struct {
		Msg string `json:"msg"`
	}
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusCreated, payload{Msg: "hello"})

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got payload
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if got.Msg != "hello" {
		t.Errorf("body.Msg = %q, want hello", got.Msg)
	}
}
