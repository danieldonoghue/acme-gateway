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
