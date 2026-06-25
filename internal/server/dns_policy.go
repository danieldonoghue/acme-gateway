package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
)

type dnsChallengeTarget struct {
	SourceDomain    string
	SourceFQDN      string
	EffectiveDomain string
	EffectiveFQDN   string
}

func (h *Handler) resolveDNSChallengeTarget(ctx context.Context, hook config.DNSHook, sourceDomain, sourceFQDN string) (dnsChallengeTarget, error) {
	target := dnsChallengeTarget{
		SourceDomain:    sourceDomain,
		SourceFQDN:      normalizeFQDN(sourceFQDN),
		EffectiveDomain: sourceDomain,
		EffectiveFQDN:   normalizeFQDN(sourceFQDN),
	}

	if !hook.Delegation.EnabledOrDefault() {
		return target, nil
	}

	effectiveFQDN, delegated, err := resolveDelegatedFQDN(ctx, target.SourceFQDN)
	if err != nil {
		if hook.Delegation.ModeOrDefault() == "permissive" {
			h.log.Warn("dns-01 delegation lookup failed; falling back to source fqdn",
				"source_fqdn", target.SourceFQDN,
				"error", err,
			)
			return target, nil
		}
		return target, err
	}
	if !delegated {
		return target, nil
	}

	if err := validateDelegatedTarget(effectiveFQDN, hook.Delegation.AllowedZoneSuffixes); err != nil {
		if hook.Delegation.ModeOrDefault() == "permissive" {
			h.log.Warn("dns-01 delegated fqdn rejected by suffix policy; falling back to source fqdn",
				"source_fqdn", target.SourceFQDN,
				"delegated_fqdn", effectiveFQDN,
				"error", err,
			)
			return target, nil
		}
		return target, err
	}

	target.EffectiveFQDN = normalizeFQDN(effectiveFQDN)
	target.EffectiveDomain = trimACMEChallengePrefix(target.EffectiveFQDN)
	return target, nil
}

func validateDelegatedTarget(effectiveFQDN string, allowedSuffixes []string) error {
	if len(allowedSuffixes) == 0 {
		return nil
	}
	trimmed := normalizeFQDN(effectiveFQDN)
	for _, suffix := range allowedSuffixes {
		s := normalizeFQDN(strings.TrimSpace(suffix))
		if s == "" {
			continue
		}
		if trimmed == s || strings.HasSuffix(trimmed, "."+s) {
			return nil
		}
	}
	return fmt.Errorf("delegated dns-01 fqdn %q does not match any allowed_zone_suffixes", effectiveFQDN)
}

func resolveDelegatedFQDN(ctx context.Context, sourceFQDN string) (effectiveFQDN string, delegated bool, err error) {
	current := normalizeFQDN(sourceFQDN)
	if current == "" {
		return "", false, fmt.Errorf("empty dns-01 source fqdn")
	}
	seen := map[string]struct{}{}
	for depth := 0; depth < 10; depth++ {
		if _, ok := seen[current]; ok {
			return "", false, fmt.Errorf("cname delegation loop detected at %q", current)
		}
		seen[current] = struct{}{}

		cname, err := lookupCNAMEOnce(ctx, current)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(strings.ToLower(dnsErr.Err), "no such host")) {
				return current, depth > 0, nil
			}
			return "", false, fmt.Errorf("lookup cname for %q: %w", current, err)
		}
		if cname == "" || normalizeFQDN(cname) == current {
			return current, depth > 0, nil
		}
		current = normalizeFQDN(cname)
	}
	return "", false, fmt.Errorf("cname delegation exceeded max depth")
}

func lookupCNAMEOnce(ctx context.Context, fqdn string) (string, error) {
	// LookupCNAME returns the canonical name if a CNAME exists; otherwise it
	// returns the query name itself or a not-found error.
	cname, err := net.DefaultResolver.LookupCNAME(ctx, fqdn)
	if err != nil {
		return "", err
	}
	return normalizeFQDN(cname), nil
}

func (h *Handler) waitForDNSPropagation(ctx context.Context, hook config.DNSHook, fqdn, expectedTXT string) error {
	if !hook.Propagation.EnabledOrDefault() {
		return nil
	}

	nsHosts, err := authoritativeNameservers(ctx, fqdn)
	if err != nil {
		return fmt.Errorf("resolving authoritative nameservers for %q: %w", fqdn, err)
	}
	if len(nsHosts) == 0 {
		return fmt.Errorf("no authoritative nameservers discovered for %q", fqdn)
	}
	nsEndpoints := resolveNameserverEndpoints(ctx, nsHosts)

	minConsecutive := hook.Propagation.MinConsecutiveOrDefault()
	quorumPercent := hook.Propagation.QuorumPercentOrDefault()
	required := quorumRequirement(len(nsHosts), quorumPercent)
	if required < 1 {
		required = 1
	}

	timeout := hook.Propagation.TimeoutOrDefault()
	poll := hook.Propagation.PollOrDefault()

	h.log.Info("dns-01 propagation wait started",
		"fqdn", fqdn,
		"nameserver_count", len(nsHosts),
		"required_quorum", required,
		"quorum_percent", quorumPercent,
		"min_consecutive", minConsecutive,
		"timeout_seconds", int(timeout.Seconds()),
		"poll_seconds", int(poll.Seconds()),
	)

	deadline := time.Now().Add(timeout)
	successes := make(map[string]int, len(nsHosts))
	for time.Now().Before(deadline) {
		stable := 0
		for _, ns := range nsHosts {
			endpoint := nsEndpoints[ns]
			if endpoint == "" {
				endpoint = ns
			}
			ok, err := queryTXTFromNameserver(ctx, endpoint, fqdn, expectedTXT)
			if err != nil {
				h.log.Debug("dns-01 propagation query failed", "fqdn", fqdn, "nameserver", ns, "nameserver_endpoint", endpoint, "error", err)
				successes[ns] = 0
				continue
			}
			if ok {
				successes[ns]++
			} else {
				successes[ns] = 0
			}
			if successes[ns] >= minConsecutive {
				stable++
			}
		}

		if stable >= required {
			h.log.Info("dns-01 propagation quorum reached",
				"fqdn", fqdn,
				"stable_nameservers", stable,
				"required_quorum", required,
			)
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("dns propagation wait canceled: %w", ctx.Err())
		case <-time.After(poll):
		}
	}

	return fmt.Errorf("dns propagation timeout for %q after %s", fqdn, timeout)
}

func authoritativeNameservers(ctx context.Context, fqdn string) ([]string, error) {
	name := normalizeFQDN(fqdn)
	if name == "" {
		return nil, fmt.Errorf("empty fqdn")
	}

	labels := strings.Split(name, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		nss, err := net.DefaultResolver.LookupNS(ctx, candidate)
		if err != nil || len(nss) == 0 {
			continue
		}
		hosts := make([]string, 0, len(nss))
		for _, ns := range nss {
			host := normalizeFQDN(ns.Host)
			if host != "" {
				hosts = append(hosts, host)
			}
		}
		slices.Sort(hosts)
		hosts = slices.Compact(hosts)
		if len(hosts) > 0 {
			return hosts, nil
		}
	}
	return nil, fmt.Errorf("no nameservers discovered")
}

func queryTXTFromNameserver(ctx context.Context, nameserverHost, fqdn, expectedTXT string) (bool, error) {
	fqdn = normalizeFQDN(fqdn)
	ns := net.JoinHostPort(strings.TrimSuffix(nameserverHost, "."), "53")
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, ns)
		},
	}
	values, err := resolver.LookupTXT(ctx, fqdn)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && (dnsErr.IsNotFound || strings.Contains(strings.ToLower(dnsErr.Err), "no such host")) {
			return false, nil
		}
		return false, err
	}
	for _, v := range values {
		if strings.TrimSpace(v) == expectedTXT {
			return true, nil
		}
	}
	return false, nil
}

func resolveNameserverEndpoints(ctx context.Context, hosts []string) map[string]string {
	endpoints := make(map[string]string, len(hosts))
	for _, host := range hosts {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			continue
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				endpoints[host] = ip.IP.String()
				break
			}
		}
		if endpoints[host] == "" {
			endpoints[host] = ips[0].IP.String()
		}
	}
	return endpoints
}

func quorumRequirement(totalNS, quorumPercent int) int {
	if totalNS <= 0 {
		return 0
	}
	if quorumPercent <= 0 {
		quorumPercent = 100
	}
	if quorumPercent > 100 {
		quorumPercent = 100
	}
	return int(math.Ceil((float64(totalNS) * float64(quorumPercent)) / 100.0))
}

func normalizeFQDN(s string) string {
	s = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(s, ".")))
	return s
}

func trimACMEChallengePrefix(fqdn string) string {
	fqdn = normalizeFQDN(fqdn)
	return strings.TrimPrefix(fqdn, "_acme-challenge.")
}
