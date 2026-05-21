// Package config loads and validates the acme-gateway configuration.
// Sensitive fields support ${ENV_VAR} interpolation.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Server    ServerConfig              `yaml:"server"`
	State     StateConfig               `yaml:"state"`
	Bootstrap BootstrapConfig           `yaml:"bootstrap"`
	Upstreams map[string]UpstreamConfig `yaml:"upstreams"`
	// Profiles advertised in /directory meta. Keys are operator-defined names;
	// values are human-readable descriptions. These have no required relationship
	// to any upstream CA's profile namespace.
	Profiles map[string]string `yaml:"profiles"`
	Routing  RoutingConfig     `yaml:"routing"`
}

// ServerConfig controls the HTTPS listener.
type ServerConfig struct {
	Listen  string `yaml:"listen"`
	BaseURL string `yaml:"base_url"`
}

// StateConfig points to the SQLite database.
type StateConfig struct {
	DBPath string `yaml:"db_path"`
}

// BootstrapConfig configures automatic certificate acquisition for the gateway itself.
type BootstrapConfig struct {
	Enabled         bool    `yaml:"enabled"`
	Upstream        string  `yaml:"upstream"`
	Domain          string  `yaml:"domain"`
	ContactEmail    string  `yaml:"contact_email"`
	Challenge       string  `yaml:"challenge"`
	CertPath        string  `yaml:"cert_path"`
	KeyPath         string  `yaml:"key_path"`
	RenewBeforeDays int     `yaml:"renew_before_days"`
	DNSHook         DNSHook `yaml:"dns_hook"`
}

// DNSHook holds paths to dns-01 hook scripts.
type DNSHook struct {
	DeployScript  string `yaml:"deploy_script"`
	CleanupScript string `yaml:"cleanup_script"`
}

// EABConfig holds External Account Binding credentials for an upstream CA.
type EABConfig struct {
	KeyID   string `yaml:"key_id"`
	HMACKey string `yaml:"hmac_key"`
}

// UpstreamConfig describes a single upstream certificate authority.
type UpstreamConfig struct {
	DirectoryURL string     `yaml:"directory_url"`
	ContactEmail string     `yaml:"contact_email"`
	EAB          *EABConfig `yaml:"eab,omitempty"`
	// AccountCount is the number of independent ACME accounts to maintain at
	// this upstream. Multiple accounts spread new-order rate limits across
	// accounts (e.g. Let's Encrypt allows 50 new orders per account per 3 h).
	// Requires no EAB; EAB upstreams need one credential set per account and
	// should instead be configured as separate upstream entries. Defaults to 1.
	AccountCount int `yaml:"account_count,omitempty"`
}

// RoutingConfig holds the ordered list of routing rules and the default upstream.
type RoutingConfig struct {
	Rules           []RoutingRule `yaml:"rules"`
	DefaultUpstream string        `yaml:"default_upstream"`
}

// RoutingRule maps a set of match conditions to a target upstream.
// UpstreamProfile controls what profile name (if any) is sent to the upstream CA:
//   - ""             → strip (omit the profile field upstream) — DEFAULT
//   - "$passthrough" → forward exactly what the client sent
//   - any other string → always send this exact string upstream
type RoutingRule struct {
	Match           MatchConfig `yaml:"match"`
	Upstream        string      `yaml:"upstream"`
	UpstreamProfile string      `yaml:"upstream_profile,omitempty"`
}

// MatchConfig holds the conditions for a routing rule. All non-empty fields are ANDed.
type MatchConfig struct {
	// Profile matches the profile name from the ACME newOrder payload.
	Profile string `yaml:"profile,omitempty"`
	// KeyType matches "RSA" or "ECDSA" based on the account's public key.
	KeyType string `yaml:"key_type,omitempty"`
	// DomainSuffix matches if any identifier in the order ends with this suffix.
	DomainSuffix string `yaml:"domain_suffix,omitempty"`
}

var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// Load reads the config file at path, performs ${ENV_VAR} interpolation, and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	interpolated := interpolateEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(interpolated), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// interpolateEnv replaces ${VAR} tokens with the corresponding environment variable.
// Tokens whose variable is not set are left unchanged.
func interpolateEnv(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		name := envVarRe.FindStringSubmatch(match)[1]
		if val, ok := os.LookupEnv(name); ok {
			return val
		}
		return match
	})
}

func validate(cfg *Config) error {
	if cfg.Server.BaseURL == "" {
		return fmt.Errorf("server.base_url is required")
	}
	if strings.HasSuffix(cfg.Server.BaseURL, "/") {
		return fmt.Errorf("server.base_url must not have a trailing slash")
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":443"
	}
	if cfg.State.DBPath == "" {
		return fmt.Errorf("state.db_path is required")
	}
	if len(cfg.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream must be configured")
	}

	// Validate each upstream.
	for name, up := range cfg.Upstreams {
		if up.DirectoryURL == "" {
			return fmt.Errorf("upstreams.%s: directory_url is required", name)
		}
		if up.AccountCount > 1 && up.EAB != nil {
			return fmt.Errorf("upstreams.%s: account_count > 1 requires no EAB (each account needs its own credential; configure separate upstream entries instead)", name)
		}
	}

	// Validate routing rules.
	for i, rule := range cfg.Routing.Rules {
		if rule.Upstream == "" {
			return fmt.Errorf("routing.rules[%d]: upstream is required", i)
		}
		if _, ok := cfg.Upstreams[rule.Upstream]; !ok {
			return fmt.Errorf("routing.rules[%d]: upstream %q not found in upstreams", i, rule.Upstream)
		}
		// Profile names referenced in match blocks must exist in the profiles map.
		if rule.Match.Profile != "" {
			if _, ok := cfg.Profiles[rule.Match.Profile]; !ok {
				return fmt.Errorf("routing.rules[%d]: profile %q not defined in profiles map", i, rule.Match.Profile)
			}
		}
		// Validate key_type values.
		kt := strings.ToUpper(rule.Match.KeyType)
		if kt != "" && kt != "RSA" && kt != "ECDSA" {
			return fmt.Errorf("routing.rules[%d]: key_type must be RSA or ECDSA, got %q", i, rule.Match.KeyType)
		}
	}

	// Validate default upstream.
	if cfg.Routing.DefaultUpstream != "" {
		if _, ok := cfg.Upstreams[cfg.Routing.DefaultUpstream]; !ok {
			return fmt.Errorf("routing.default_upstream %q not found in upstreams", cfg.Routing.DefaultUpstream)
		}
	}

	// Validate bootstrap upstream if enabled.
	if cfg.Bootstrap.Enabled {
		if cfg.Bootstrap.Upstream == "" {
			return fmt.Errorf("bootstrap.upstream is required when bootstrap is enabled")
		}
		if _, ok := cfg.Upstreams[cfg.Bootstrap.Upstream]; !ok {
			return fmt.Errorf("bootstrap.upstream %q not found in upstreams", cfg.Bootstrap.Upstream)
		}
		if cfg.Bootstrap.Domain == "" {
			return fmt.Errorf("bootstrap.domain is required when bootstrap is enabled")
		}
		if cfg.Bootstrap.CertPath == "" || cfg.Bootstrap.KeyPath == "" {
			return fmt.Errorf("bootstrap.cert_path and bootstrap.key_path are required when bootstrap is enabled")
		}
	} else {
		// bootstrap.enabled: false means the operator provides the cert externally.
		if cfg.Bootstrap.CertPath == "" || cfg.Bootstrap.KeyPath == "" {
			return fmt.Errorf("bootstrap.cert_path and bootstrap.key_path are required when bootstrap.enabled is false (externally-managed cert)")
		}
	}

	return nil
}
