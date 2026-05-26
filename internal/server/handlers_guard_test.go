package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCSRKeyTypeFromDER_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.internal"},
		DNSNames: []string{"example.internal"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	got, err := csrKeyTypeFromDER(der)
	if err != nil {
		t.Fatalf("csrKeyTypeFromDER: %v", err)
	}
	if got != "ECDSA" {
		t.Fatalf("csr key type = %q, want ECDSA", got)
	}
}

func TestCSRKeyTypeFromDER_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.internal"},
		DNSNames: []string{"example.internal"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	got, err := csrKeyTypeFromDER(der)
	if err != nil {
		t.Fatalf("csrKeyTypeFromDER: %v", err)
	}
	if got != "RSA" {
		t.Fatalf("csr key type = %q, want RSA", got)
	}
}

func TestCSRKeyTypeFromDER_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.internal"},
		DNSNames: []string{"example.internal"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	got, err := csrKeyTypeFromDER(der)
	if err != nil {
		t.Fatalf("csrKeyTypeFromDER: %v", err)
	}
	if got != "Ed25519" {
		t.Fatalf("csr key type = %q, want Ed25519", got)
	}
}

func TestCSRKeyTypeFromDER_InvalidCSR(t *testing.T) {
	_, err := csrKeyTypeFromDER([]byte("not a csr"))
	if err == nil {
		t.Fatal("expected parse error for invalid CSR")
	}
}
