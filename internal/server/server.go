package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server is the ACMEv2 gateway HTTPS server.
type Server struct {
	handler *Handler
	log     *slog.Logger

	certMu  sync.RWMutex
	tlsCert *tls.Certificate

	httpServer *http.Server
}

// NewServer creates an HTTP server with the given handler.
func NewServer(h *Handler, log *slog.Logger) *Server {
	return &Server{handler: h, log: log}
}

// SetCertificate updates the TLS certificate used by the server.
// Safe to call from a background goroutine during live reload.
func (s *Server) SetCertificate(cert *tls.Certificate) {
	s.certMu.Lock()
	s.tlsCert = cert
	s.certMu.Unlock()
}

// ListenAndServeTLS starts the HTTPS server on addr using the already-set certificate.
func (s *Server) ListenAndServeTLS(addr string) error {
	mux := s.buildRouter()

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.certMu.RLock()
			cert := s.tlsCert
			s.certMu.RUnlock()
			if cert == nil {
				return nil, fmt.Errorf("no TLS certificate loaded")
			}
			return cert, nil
		},
	}

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.log.Info("HTTPS listener starting", "addr", addr)
	// Empty strings because certificate is provided via GetCertificate.
	return s.httpServer.ListenAndServeTLS("", "")
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// buildRouter wires up all ACME endpoints per RFC 8555.
func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)

	h := s.handler

	// Directory
	r.Get("/directory", h.handleDirectory)

	// Nonce
	r.Head("/new-nonce", h.handleNewNonce)
	r.Get("/new-nonce", h.handleNewNonce)

	// Account
	r.Post("/new-account", h.handleNewAccount)

	// Order flow
	r.Post("/new-order", h.handleNewOrder)
	r.Post("/order/{id}", h.handleOrder)
	r.Post("/authz/{id}", h.handleAuthz)
	r.Post("/challenge/{id}", h.handleChallenge)
	r.Post("/finalize/{id}", h.handleFinalize)

	// Certificate: GET for legacy clients; POST-as-GET (RFC 8555 §7.4.2) for compliant ones.
	r.Get("/cert/{id}", h.handleCert)
	r.Post("/cert/{id}", h.handleCert)

	// Key roll-over (RFC 8555 §7.1.1 required; not implemented, returns 501)
	r.Post("/key-change", h.handleKeyChange)

	// Revocation
	r.Post("/revoke-cert", h.handleRevokeCert)

	return r
}
