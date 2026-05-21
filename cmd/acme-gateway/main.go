// Command acme-gateway is an ACMEv2 (RFC 8555) gateway that terminates inbound
// ACME requests and re-originates them to one of several upstream CAs based on
// operator-defined routing rules.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/bootstrap"
	"github.com/danieldonoghue/acme-gateway/internal/config"
	"github.com/danieldonoghue/acme-gateway/internal/router"
	"github.com/danieldonoghue/acme-gateway/internal/server"
	"github.com/danieldonoghue/acme-gateway/internal/store"
	"github.com/danieldonoghue/acme-gateway/internal/upstream"
)

// Build-time variables injected by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("acme-gateway starting", "version", version, "commit", commit, "date", date)

	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	// ── Load config ──────────────────────────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	log.Info("config loaded", "path", cfgPath)

	// ── Open state store ─────────────────────────────────────────────────────
	st, err := store.New(cfg.State.DBPath)
	if err != nil {
		return fmt.Errorf("opening state store: %w", err)
	}
	defer st.Close()
	log.Info("state store opened", "path", cfg.State.DBPath)

	// Prune expired nonces from previous runs.
	if err := st.PruneExpiredNonces(context.Background()); err != nil {
		log.Warn("pruning nonces", "err", err)
	}

	// ── Bootstrap gateway certificate ────────────────────────────────────────
	var srv *server.Server

	r := router.New(&cfg.Routing)
	pool := upstream.NewPool(cfg, st)
	h := server.NewHandler(cfg, st, r, pool, log)
	srv = server.NewServer(h, log)

	if cfg.Bootstrap.Enabled {
		upCfg := cfg.Upstreams[cfg.Bootstrap.Upstream]

		mgr := bootstrap.NewManager(
			&cfg.Bootstrap,
			&upCfg,
			log,
			func(cert *tls.Certificate) {
				srv.SetCertificate(cert)
				log.Info("certificate reloaded", "domain", cfg.Bootstrap.Domain)
			},
		)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		tlsCert, err := mgr.Bootstrap(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("bootstrapping certificate: %w", err)
		}
		srv.SetCertificate(tlsCert)

		// Start renewal loop (uses the same manager so onRenew fires on reload).
		renewCtx, renewCancel := context.WithCancel(context.Background())
		defer renewCancel()
		mgr.StartRenewalLoop(renewCtx, tlsCert)
	} else {
		// Externally-managed certificate: load the keypair from disk once at
		// startup. cert_path and key_path are validated by config.Load.
		//
		// NOTE: there is no live-reload for the external path. If an external
		// renewer (cert-manager, Ansible cron, etc.) rewrites the files, the
		// gateway must be restarted to pick up the new certificate.
		// See docs/decisions/0003-no-live-reload-external-cert.md.
		tlsCert, err := tls.LoadX509KeyPair(cfg.Bootstrap.CertPath, cfg.Bootstrap.KeyPath)
		if err != nil {
			return fmt.Errorf("loading external TLS certificate: %w", err)
		}
		srv.SetCertificate(&tlsCert)
		log.Info("external certificate loaded",
			"cert_path", cfg.Bootstrap.CertPath,
			"key_path", cfg.Bootstrap.KeyPath,
		)
	}

	// ── Start background nonce pruner ─────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := st.PruneExpiredNonces(context.Background()); err != nil {
				log.Warn("pruning nonces", "err", err)
			}
		}
	}()

	// ── Start HTTPS listener ─────────────────────────────────────────────────
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS(cfg.Server.Listen)
	}()

	// ── Wait for shutdown signal ─────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		log.Info("shutting down", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
