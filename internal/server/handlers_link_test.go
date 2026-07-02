package server

import (
	"testing"

	"github.com/danieldonoghue/acme-gateway/internal/config"
)

func TestUpLinkHeader(t *testing.T) {
	h := &Handler{cfg: &config.Config{Server: config.ServerConfig{BaseURL: "https://gw.example.com"}}}

	got := h.upLinkHeader("https://gw.example.com/authz/abc123")
	want := `<https://gw.example.com/authz/abc123>;rel="up"`
	if got != want {
		t.Fatalf("upLinkHeader() = %q, want %q", got, want)
	}
}

func TestAlternateLinkHeader(t *testing.T) {
	h := &Handler{cfg: &config.Config{Server: config.ServerConfig{BaseURL: "https://gw.example.com"}}}

	got := h.alternateLinkHeader("https://gw.example.com/cert/abc123")
	want := `<https://gw.example.com/cert/abc123>;rel="alternate"`
	if got != want {
		t.Fatalf("alternateLinkHeader() = %q, want %q", got, want)
	}
}
