package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// CA signs client certificates using a loaded certificate authority keypair.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	serial  *big.Int
	mu      sync.Mutex
}

// LoadCA reads a PEM-encoded CA certificate and private key from disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CA cert %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	var keyBlock *pem.Block
	rest := keyPEM
	for {
		keyBlock, rest = pem.Decode(rest)
		if keyBlock == nil {
			return nil, fmt.Errorf("no EC PRIVATE KEY block in %s", keyPath)
		}
		if keyBlock.Type == "EC PRIVATE KEY" {
			break
		}
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		return nil, fmt.Errorf("CA cert and key do not match")
	}

	// Seed serial from crypto/rand to avoid collisions across restarts.
	seed, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("seed serial: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM, serial: seed}, nil
}

// IssueCert generates an ECDSA P-256 keypair and signs a client certificate
// with the given username as the Subject CN. The returned PEM data is
// ready for use with Docker CLI contexts.
func (ca *CA) IssueCert(username string) (certPEM, keyPEM []byte, err error) {
	ca.mu.Lock()
	ca.serial.Add(ca.serial, big.NewInt(1))
	serial := new(big.Int).Set(ca.serial)
	ca.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: username},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// CACertPEM returns the CA certificate as PEM-encoded bytes.
func (ca *CA) CACertPEM() []byte {
	return ca.certPEM
}
