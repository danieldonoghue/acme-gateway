//go:build e2e

package e2e_test

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func runDNSHook(t *testing.T, phase, command, fqdn, dnsValue, token, keyAuthorization string) {
	t.Helper()
	if err := runDNSHookCommand(phase, command, fqdn, dnsValue, token, keyAuthorization); err != nil {
		t.Fatalf("dns hook (%s) failed: %v", phase, err)
	}
}

func runDNSHookCommand(phase, command, fqdn, dnsValue, token, keyAuthorization string) error {
	domain := strings.TrimPrefix(fqdn, "_acme-challenge.")

	cmd := exec.Command("sh", "-c", command)
	cmd.Env = append(os.Environ(),
		"ACME_E2E_PHASE="+phase,
		"ACME_E2E_FQDN="+fqdn,
		"ACME_E2E_DNS_VALUE="+dnsValue,
		"ACME_E2E_TOKEN="+token,
		"ACME_E2E_KEY_AUTHORIZATION="+keyAuthorization,
		"CERTBOT_DOMAIN="+domain,
		"CERTBOT_VALIDATION="+dnsValue,
		"CERTBOT_TOKEN="+token,
		"ACME_GATEWAY_FQDN="+fqdn,
		"ACME_GATEWAY_DOMAIN="+domain,
		"ACME_GATEWAY_DNS_VALUE="+dnsValue,
		"ACME_GATEWAY_TOKEN="+token,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\noutput:\n%s", err, string(out))
	}
	if len(out) > 0 {
		log.Printf("[lego-dns] %s output:\n%s", phase, string(out))
	}
	return nil
}

func waitForAuthoritativeTXT(fqdn, want string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	nsHosts, nsErr := authoritativeNameservers(fqdn)
	if nsErr == nil && len(nsHosts) > 0 {
		log.Printf("[lego-dns] authoritative nameservers for %s: %v", fqdn, nsHosts)
	}

	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		if len(nsHosts) > 0 {
			missing := make([]string, 0, len(nsHosts))
			for _, ns := range nsHosts {
				txts, err := lookupTXTAtNameserver(fqdn, ns)
				if err != nil {
					missing = append(missing, ns+"(lookup failed)")
					continue
				}
				found := false
				for _, v := range txts {
					if v == want {
						found = true
						break
					}
				}
				if !found {
					missing = append(missing, ns)
				}
			}
			if len(missing) == 0 {
				log.Printf("[lego-dns] authoritative TXT visible for %s after %d attempt(s)", fqdn, attempt)
				return nil
			}
			if attempt == 1 || attempt%6 == 0 {
				log.Printf("[lego-dns] authoritative TXT not yet visible for %s; missing=%v", fqdn, missing)
			}
		} else {
			txts, err := net.LookupTXT(fqdn)
			if err == nil {
				for _, v := range txts {
					if v == want {
						log.Printf("[lego-dns] recursive TXT visible for %s after %d attempt(s)", fqdn, attempt)
						return nil
					}
				}
			}
		}
		time.Sleep(interval)
	}

	return fmt.Errorf("authoritative TXT propagation timeout after %s for %s", timeout, fqdn)
}

// cnameTarget returns the CNAME target of fqdn (no trailing dot), or "" if fqdn
// is not a CNAME. Used to follow acme-dns-style dns-01 delegation to the zone
// where the challenge TXT actually lives. Best-effort via `dig`; on any failure
// it returns "" so callers fall back to the original name.
func cnameTarget(fqdn string) string {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	out, err := exec.Command("dig", "+short", name, "CNAME").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	target := strings.TrimSuffix(line, ".")
	if target == "" || strings.EqualFold(target, name) {
		return ""
	}
	return target
}

func waitForTXTRecord(t *testing.T, fqdn, want string) bool {
	t.Helper()

	timeout := envDurationSeconds("ACME_E2E_DNS_TIMEOUT_SECONDS", 300)
	interval := envDurationSeconds("ACME_E2E_DNS_POLL_SECONDS", 5)

	// If the challenge name is CNAME-delegated (acme-dns style), the TXT lives at
	// the delegated target, not at _acme-challenge.<domain>. Follow it so NS
	// discovery and the TXT checks hit the right zone — exactly what the CA does.
	if target := cnameTarget(fqdn); target != "" {
		testLogf(t, "test", "%s is CNAME-delegated -> %s; verifying TXT at the delegated target", fqdn, target)
		fqdn = target
	}

	nsHosts, nsErr := authoritativeNameservers(fqdn)
	if nsErr != nil {
		testLogf(t, "test", "warning: could not resolve authoritative nameservers for %s: %v", fqdn, nsErr)
	}
	if len(nsHosts) > 0 {
		testLogf(t, "test", "authoritative nameservers for %s: %v", fqdn, nsHosts)
	}

	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++

		var matched bool
		if len(nsHosts) > 0 {
			missing := make([]string, 0, len(nsHosts))
			successfulNS := make([]string, 0, len(nsHosts))
			for _, ns := range nsHosts {
				txts, err := lookupTXTAtNameserver(fqdn, ns)
				if err != nil {
					missing = append(missing, ns+"(lookup failed)")
					if attempt == 1 {
						testLogf(t, "test", "DEBUG: ns %s lookup error: %v", ns, err)
					}
					continue
				}
				testLogf(t, "test", "DEBUG: ns %s returned %d TXT records", ns, len(txts))
				nsMatched := false
				for _, v := range txts {
					testLogf(t, "test", "DEBUG: ns %s has TXT: %s", ns, v)
					if v == want {
						nsMatched = true
						break
					}
				}
				if !nsMatched {
					missing = append(missing, ns)
				} else {
					successfulNS = append(successfulNS, ns)
				}
			}
			matched = len(missing) == 0
			if !matched && (attempt == 1 || attempt%6 == 0) {
				testLogf(t, "test", "TXT not yet visible on all authoritative NS for %s; still missing on: %v", fqdn, missing)
			}
			if matched {
				testLogf(t, "test", "TXT record now visible on all authoritative NS for %s (found after %d attempts, successful NS: %v)", fqdn, attempt, successfulNS)
				return true
			}
		} else {
			// Fallback if NS discovery fails.
			testLogf(t, "test", "DEBUG: NS discovery failed, falling back to recursive resolver for %s", fqdn)
			txts, err := net.LookupTXT(fqdn)
			if err != nil {
				testLogf(t, "test", "DEBUG: recursive lookup failed for %s: %v", fqdn, err)
			} else {
				testLogf(t, "test", "DEBUG: recursive lookup returned %d TXT records for %s", len(txts), fqdn)
				for _, v := range txts {
					if v == want {
						testLogf(t, "test", "DEBUG: found matching TXT record via recursive resolver after %d attempts", attempt)
						matched = true
						break
					}
				}
			}
			if matched {
				return true
			}
		}

		if matched {
			return true
		}
		timeLeft := time.Until(deadline)
		if attempt == 1 || attempt%6 == 0 {
			testLogf(t, "test", "DEBUG: waitForTXTRecord still waiting (attempt %d, %v remaining)", attempt, timeLeft)
		}
		time.Sleep(interval)
	}
	testLogf(t, "test", "TXT propagation timeout after %s for %s (wanted %q)", timeout, fqdn, want)
	return false
}

func waitForTXTRecordInBind(t *testing.T, fqdn, want string) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		cmd := exec.Command("docker", "exec", "e2e-bind-1", "dig", "+short", "@localhost", fqdn, "TXT")
		out, err := cmd.CombinedOutput()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				v := strings.TrimSpace(strings.Trim(line, "\""))
				if v == want {
					t.Logf("BIND confirmed TXT for %s after %d attempt(s)", fqdn, attempt)
					return
				}
			}
			if attempt == 1 || attempt%5 == 0 {
				t.Logf("BIND TXT not ready yet for %s (attempt %d), dig=%q", fqdn, attempt, strings.TrimSpace(string(out)))
			}
		} else if attempt == 1 || attempt%5 == 0 {
			t.Logf("BIND TXT check failed for %s (attempt %d): %v", fqdn, attempt, err)
		}

		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("timeout waiting for BIND TXT record for %s (wanted %q)", fqdn, want)
}

func dns01TXTFromTokenAndPEMKey(token string, keyPEM []byte) (string, string, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", "", fmt.Errorf("decode PEM: no key block")
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return "", "", fmt.Errorf("parse private key: %w", err)
		}
		keyAny = ecKey
	}

	pubKey, err := accountPublicKey(keyAny)
	if err != nil {
		return "", "", err
	}
	jwk := jose.JSONWebKey{Key: pubKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", "", err
	}

	keyAuth := token + "." + base64.RawURLEncoding.EncodeToString(thumbprint)
	sum := sha256.Sum256([]byte(keyAuth))
	return keyAuth, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func authoritativeNameservers(fqdn string) ([]string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if name == "" {
		return nil, fmt.Errorf("empty fqdn")
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return nil, fmt.Errorf("invalid fqdn %q", fqdn)
	}

	for i := 0; i <= len(labels)-2; i++ {
		candidate := strings.Join(labels[i:], ".")
		nsRecords, err := net.LookupNS(candidate)
		if err != nil || len(nsRecords) == 0 {
			continue
		}

		hosts := make([]string, 0, len(nsRecords))
		seen := map[string]struct{}{}
		for _, ns := range nsRecords {
			h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
		if len(hosts) > 0 {
			return hosts, nil
		}
	}

	return nil, fmt.Errorf("no authoritative nameservers found for %q", fqdn)
}

func lookupTXTAtNameserver(fqdn, nsHost string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// First, resolve the nameserver hostname to IP(s) using system resolver
	ips, err := net.LookupIP(nsHost)
	if err != nil {
		return nil, fmt.Errorf("resolve nameserver %s: %w", nsHost, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for nameserver %s", nsHost)
	}

	// Use the first IP to query
	nsIP := ips[0].String()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", net.JoinHostPort(nsIP, "53"))
		},
	}

	return r.LookupTXT(ctx, strings.TrimSuffix(fqdn, "."))
}

func verifySOAConsistency(t *testing.T, domain string) {
	t.Helper()

	nsHosts, err := authoritativeNameservers(domain)
	if err != nil {
		t.Logf("WARNING: could not resolve authoritative nameservers: %v", err)
		return
	}
	if len(nsHosts) == 0 {
		t.Logf("WARNING: no authoritative nameservers found for %s", domain)
		return
	}

	// Query SOA from each nameserver
	soaSerials := make(map[string]string)
	for _, ns := range nsHosts {
		ips, ipErr := net.LookupIP(ns)
		if ipErr != nil || len(ips) == 0 {
			t.Logf("DEBUG: ns %s IP resolution failed: %v", ns, ipErr)
			soaSerials[ns] = "ERROR"
			continue
		}
		nsIP := ips[0].String()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", net.JoinHostPort(nsIP, "53"))
			},
		}

		// Use LookupNS to get SOA details (this is a workaround; ideally we'd query SOA directly)
		// For now, just log NS to verify connectivity
		nss, err := r.LookupNS(ctx, domain)
		cancel()
		if err != nil {
			t.Logf("DEBUG: ns %s SOA query failed: %v", ns, err)
			soaSerials[ns] = "ERROR"
			continue
		}
		if len(nss) > 0 {
			t.Logf("DEBUG: ns %s responding (found %d NS records)", ns, len(nss))
			soaSerials[ns] = "OK"
		}
	}

	// Check if all NS are responding
	errCount := 0
	for ns, status := range soaSerials {
		if status == "ERROR" {
			t.Logf("DEBUG: nameserver %s not responding", ns)
			errCount++
		}
	}
	if errCount > 0 {
		t.Logf("WARNING: %d/%d nameservers not responding for SOA check", errCount, len(nsHosts))
	} else {
		t.Logf("DEBUG: all %d authoritative nameservers responding consistently", len(nsHosts))
	}
}
