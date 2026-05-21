package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

const validConfig = `
server:
  listen: ":8443"
  base_url: "https://acme-gateway.internal"

state:
  db_path: "/tmp/test.db"

upstreams:
  letsencrypt:
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    contact_email: "admin@example.com"

profiles:
  tlsserver: "Server certificate via Let's Encrypt"

routing:
  rules:
    - match:
        profile: "tlsserver"
      upstream: letsencrypt
  default_upstream: letsencrypt
`

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTemp(t, validConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.BaseURL != "https://acme-gateway.internal" {
		t.Errorf("base_url = %q, want %q", cfg.Server.BaseURL, "https://acme-gateway.internal")
	}
	if cfg.Server.Listen != ":8443" {
		t.Errorf("listen = %q, want %q", cfg.Server.Listen, ":8443")
	}
	if len(cfg.Upstreams) != 1 {
		t.Errorf("want 1 upstream, got %d", len(cfg.Upstreams))
	}
	if len(cfg.Routing.Rules) != 1 {
		t.Errorf("want 1 rule, got %d", len(cfg.Routing.Rules))
	}
}

func TestLoad_DefaultListen(t *testing.T) {
	cfg := `
server:
  base_url: "https://acme-gateway.internal"
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
routing:
  default_upstream: le
`
	path := writeTemp(t, cfg)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Server.Listen != ":443" {
		t.Errorf("listen default = %q, want %q", got.Server.Listen, ":443")
	}
}

func TestLoad_MissingBaseURL(t *testing.T) {
	cfg := `
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://example.com"
`
	path := writeTemp(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing base_url")
	}
}

func TestLoad_TrailingSlashBaseURL(t *testing.T) {
	cfg := `
server:
  base_url: "https://acme-gateway.internal/"
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://example.com"
`
	path := writeTemp(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for trailing slash in base_url")
	}
}

func TestLoad_UnknownUpstreamInRule(t *testing.T) {
	cfg := `
server:
  base_url: "https://acme-gateway.internal"
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://example.com"
profiles:
  myprofile: "desc"
routing:
  rules:
    - match:
        profile: "myprofile"
      upstream: nonexistent
`
	path := writeTemp(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown upstream in rule")
	}
}

func TestLoad_ProfileInRuleNotInProfilesMap(t *testing.T) {
	cfg := `
server:
  base_url: "https://acme-gateway.internal"
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://example.com"
routing:
  rules:
    - match:
        profile: "undefined-profile"
      upstream: le
`
	path := writeTemp(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for profile in rule not in profiles map")
	}
}

func TestLoad_InvalidKeyType(t *testing.T) {
	cfg := `
server:
  base_url: "https://acme-gateway.internal"
state:
  db_path: "/tmp/test.db"
upstreams:
  le:
    directory_url: "https://example.com"
routing:
  rules:
    - match:
        key_type: "DSA"
      upstream: le
`
	path := writeTemp(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid key_type")
	}
}

func TestInterpolateEnv(t *testing.T) {
	t.Setenv("TEST_SECRET", "my-secret-value")

	input := "key_id: ${TEST_SECRET}"
	got := interpolateEnv(input)
	want := "key_id: my-secret-value"
	if got != want {
		t.Errorf("interpolateEnv = %q, want %q", got, want)
	}
}

func TestInterpolateEnv_UnsetVar(t *testing.T) {
	os.Unsetenv("DEFINITELY_NOT_SET_ACME_GW")
	input := "key_id: ${DEFINITELY_NOT_SET_ACME_GW}"
	got := interpolateEnv(input)
	if got != input {
		t.Errorf("unset var should be left unchanged, got %q", got)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_EABConfig(t *testing.T) {
	t.Setenv("DIGICERT_KID", "kid-value")
	t.Setenv("DIGICERT_HMAC", "hmac-value")

	cfg := `
server:
  base_url: "https://acme-gateway.internal"
state:
  db_path: "/tmp/test.db"
upstreams:
  digicert:
    directory_url: "https://acme.digicert.com/v2/acme/directory"
    contact_email: "admin@example.com"
    eab:
      key_id: "${DIGICERT_KID}"
      hmac_key: "${DIGICERT_HMAC}"
routing:
  default_upstream: digicert
`
	path := writeTemp(t, cfg)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dc := got.Upstreams["digicert"]
	if dc.EAB == nil {
		t.Fatal("EAB config should not be nil")
	}
	if dc.EAB.KeyID != "kid-value" {
		t.Errorf("EAB.KeyID = %q, want %q", dc.EAB.KeyID, "kid-value")
	}
	if dc.EAB.HMACKey != "hmac-value" {
		t.Errorf("EAB.HMACKey = %q, want %q", dc.EAB.HMACKey, "hmac-value")
	}
}
