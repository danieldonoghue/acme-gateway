package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieldonoghue/acme-gateway/internal/config"
)

// ── atomicWrite ───────────────────────────────────────────────────────────────

func TestAtomicWrite_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := atomicWrite(path, []byte("hello"), 0600); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestAtomicWrite_Overwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	atomicWrite(path, []byte("first"), 0600)  //nolint:errcheck
	atomicWrite(path, []byte("second"), 0600) //nolint:errcheck

	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Errorf("content after overwrite = %q, want second", got)
	}
}

func TestAtomicWrite_DirNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent_dir", "out.txt")
	err := atomicWrite(path, []byte("data"), 0600)
	if err == nil {
		t.Fatal("expected error writing to path in nonexistent directory")
	}
}

// ── buildCSR ──────────────────────────────────────────────────────────────────

func TestBuildCSR_ValidDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	der, err := buildCSR(key, "example.com")
	if err != nil {
		t.Fatalf("buildCSR: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("expected non-empty DER")
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", csr.DNSNames)
	}
}

// ── x509LeafNotAfter ─────────────────────────────────────────────────────────

func TestX509LeafNotAfter_ReturnsNotAfter(t *testing.T) {
	want := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	cert := makeTLSCert(t, time.Now().Add(-time.Minute), want)

	got := x509LeafNotAfter(cert)
	// Allow one-second tolerance for certificate encoding.
	if got.Sub(want).Abs() > time.Second {
		t.Errorf("NotAfter = %v, want ~%v", got, want)
	}
}

func TestX509LeafNotAfter_NilCert(t *testing.T) {
	if !x509LeafNotAfter(nil).IsZero() {
		t.Error("expected zero time for nil cert")
	}
}

func TestX509LeafNotAfter_EmptyChain(t *testing.T) {
	cert := &tls.Certificate{}
	if !x509LeafNotAfter(cert).IsZero() {
		t.Error("expected zero time for cert with empty chain")
	}
}

// ── isExpiringSoon ────────────────────────────────────────────────────────────

func TestIsExpiringSoon_Yes(t *testing.T) {
	m := managerWithRenewDays(t, 30)
	// Expires in 10 days — within the 30-day window.
	cert := makeTLSCert(t, time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour))
	if !m.isExpiringSoon(cert) {
		t.Error("expected isExpiringSoon = true for cert expiring in 10 days (window 30)")
	}
}

func TestIsExpiringSoon_No(t *testing.T) {
	m := managerWithRenewDays(t, 30)
	// Expires in 60 days — outside the 30-day window.
	cert := makeTLSCert(t, time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	if m.isExpiringSoon(cert) {
		t.Error("expected isExpiringSoon = false for cert expiring in 60 days (window 30)")
	}
}

func TestIsExpiringSoon_NilCert(t *testing.T) {
	m := managerWithRenewDays(t, 30)
	if !m.isExpiringSoon(nil) {
		t.Error("expected isExpiringSoon = true for nil cert")
	}
}

// ── DNSTXT ───────────────────────────────────────────────────────────────────

func TestDNSTXT_NonEmpty(t *testing.T) {
	val, err := DNSTXT("my-token.my-thumbprint")
	if err != nil {
		t.Fatalf("DNSTXT: %v", err)
	}
	if val == "" {
		t.Fatal("expected non-empty DNS TXT value")
	}
}

func TestDNSTXT_Stable(t *testing.T) {
	v1, _ := DNSTXT("token.thumbprint")
	v2, _ := DNSTXT("token.thumbprint")
	if v1 != v2 {
		t.Error("DNSTXT is not deterministic")
	}
}

func TestDNSTXT_EmptyInput(t *testing.T) {
	_, err := DNSTXT("")
	if err == nil {
		t.Fatal("expected error for empty key authorisation")
	}
}

func TestDNSTXT_DifferentInputs(t *testing.T) {
	v1, _ := DNSTXT("token.thumbprint-A")
	v2, _ := DNSTXT("token.thumbprint-B")
	if v1 == v2 {
		t.Error("DNSTXT produced the same value for different inputs")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// managerWithRenewDays returns a minimal Manager with RenewBeforeDays set.
func managerWithRenewDays(t *testing.T, days int) *Manager {
	t.Helper()
	cfg := &config.BootstrapConfig{
		RenewBeforeDays: days,
		CertPath:        filepath.Join(t.TempDir(), "cert.pem"),
		KeyPath:         filepath.Join(t.TempDir(), "key.pem"),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewManager(cfg, &config.UpstreamConfig{}, log, nil)
}

// makeTLSCert creates a minimal self-signed tls.Certificate with the given
// validity window. The returned certificate contains a parsed leaf.
func makeTLSCert(t *testing.T, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &tlsCert
}
