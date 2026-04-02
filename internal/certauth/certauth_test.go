package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testCA writes a self-signed CA cert+key to temp files and returns their paths.
func testCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	certPath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func TestLoadCA_Valid(t *testing.T) {
	certPath, keyPath := testCA(t)

	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if ca.cert == nil || ca.key == nil {
		t.Fatal("cert or key is nil")
	}
}

func TestLoadCA_MismatchedKey(t *testing.T) {
	certPath, _ := testCA(t)

	// Generate a different key and write it.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(otherKey)
	otherKeyPath := filepath.Join(t.TempDir(), "other-key.pem")
	if err := os.WriteFile(otherKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadCA(certPath, otherKeyPath)
	if err == nil {
		t.Fatal("expected error for mismatched key")
	}
}

func TestLoadCA_MissingCertFile(t *testing.T) {
	_, keyPath := testCA(t)
	_, err := LoadCA("/nonexistent/cert.pem", keyPath)
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestLoadCA_MissingKeyFile(t *testing.T) {
	certPath, _ := testCA(t)
	_, err := LoadCA(certPath, "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestLoadCA_InvalidCertPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(certPath, []byte("not pem data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, keyPath := testCA(t)

	_, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestLoadCA_InvalidKeyPEM(t *testing.T) {
	certPath, _ := testCA(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not pem data"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadCA(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
}

func TestLoadCA_RSAKey(t *testing.T) {
	certPath, _ := testCA(t)

	// Generate an RSA key instead of ECDSA.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	rsaKeyPath := filepath.Join(t.TempDir(), "rsa-key.pem")
	if err := os.WriteFile(rsaKeyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadCA(certPath, rsaKeyPath)
	if err == nil {
		t.Fatal("expected error for RSA key (only ECDSA supported)")
	}
}

func TestIssueCert(t *testing.T) {
	certPath, keyPath := testCA(t)
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	certPEM, keyPEM, err := ca.IssueCert("alice")
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Parse the issued certificate.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in issued cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}

	if cert.Subject.CommonName != "alice" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "alice")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.NotBefore.After(time.Now()) {
		t.Errorf("NotBefore = %v, expected before now", cert.NotBefore)
	}
	if cert.NotAfter.Before(time.Now().Add(364 * 24 * time.Hour)) {
		t.Errorf("NotAfter = %v, expected ~1 year from now", cert.NotAfter)
	}

	// Verify the cert is signed by the CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("cert does not verify against CA: %v", err)
	}

	// Parse the private key.
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("no PEM block in issued key")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse issued key: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("key curve = %v, want P-256", key.Curve)
	}
	// Verify the key matches the cert.
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("issued cert and key do not match")
	}
}

func TestIssueCert_UniqueSerialsParallel(t *testing.T) {
	certPath, keyPath := testCA(t)
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	const n = 50
	serials := make([]*big.Int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			certPEM, _, err := ca.IssueCert("user")
			if err != nil {
				t.Errorf("IssueCert: %v", err)
				return
			}
			block, _ := pem.Decode(certPEM)
			cert, _ := x509.ParseCertificate(block.Bytes)
			serials[idx] = cert.SerialNumber
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool)
	for _, s := range serials {
		if s == nil {
			continue
		}
		k := s.String()
		if seen[k] {
			t.Fatalf("duplicate serial: %s", k)
		}
		seen[k] = true
	}
}

func TestCACertPEM(t *testing.T) {
	certPath, keyPath := testCA(t)
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	caPEM := ca.CACertPEM()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("no PEM block in CA cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Test CA")
	}
}
