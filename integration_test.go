package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA holds a self-signed CA certificate and key for test use.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &testCA{cert: cert, key: key, certPEM: caPEM}
}

// issueCert creates a TLS certificate signed by the CA.
func (ca *testCA) issueCert(t *testing.T, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCert
}

// writePEM writes PEM data to a temporary file and returns the path.
func writePEM(t *testing.T, data []byte, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeCertAndKey writes a tls.Certificate's cert and key PEM to temp files.
func writeCertAndKey(t *testing.T, cert tls.Certificate, prefix string) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	certPath = filepath.Join(dir, prefix+".crt")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyPath = filepath.Join(dir, prefix+".key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

// serverTemplate returns a certificate template suitable for a localhost server.
func serverTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// clientTemplate returns a certificate template for client authentication.
func clientTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "proxy-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// dockerMock returns an http.Handler that echoes the request path as JSON.
func dockerMock() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"path":%q,"method":%q}`, r.URL.Path, r.Method)
	})
}

// startTCPServer starts a plain HTTP server on a random TCP port.
func startTCPServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// startTLSServer starts a TLS HTTP server. If clientCA is non-nil, mTLS is required.
func startTLSServer(t *testing.T, handler http.Handler, serverCert tls.Certificate, clientCA *x509.CertPool) string {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	if clientCA != nil {
		tlsCfg.ClientCAs = clientCA
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// TestIntegration_PlainProxy_PlainTCPBackend verifies basic TCP proxying
// without any TLS (baseline for comparison).
func TestIntegration_PlainProxy_PlainTCPBackend(t *testing.T) {
	addr := startTCPServer(t, dockerMock())

	b := backend{network: "tcp", address: addr}
	proxy := newProxy(b)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/v1.45/containers/json") {
		t.Errorf("unexpected body: %s", body)
	}
}

// TestIntegration_PlainProxy_TLSBackend verifies the main bug fix:
// a plain HTTP proxy forwarding to a TLS-protected backend (server auth only).
func TestIntegration_PlainProxy_TLSBackend(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	addr := startTLSServer(t, dockerMock(), serverCert, nil)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	b := backend{
		network:   "tcp",
		address:   addr,
		tlsConfig: &tls.Config{RootCAs: caPool},
	}
	proxy := newProxy(b)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/v1.45/info") {
		t.Errorf("unexpected body: %s", body)
	}
}

// TestIntegration_PlainProxy_MTLSBackend verifies proxying to a backend
// that requires mutual TLS (client certificate authentication).
func TestIntegration_PlainProxy_MTLSBackend(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplate())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	addr := startTLSServer(t, dockerMock(), serverCert, caPool)

	b := backend{
		network: "tcp",
		address: addr,
		tlsConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}
	proxy := newProxy(b)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/v1.45/containers/json") {
		t.Errorf("unexpected body: %s", body)
	}
}

// TestIntegration_MTLSBackend_RejectsWithoutClientCert verifies that the
// mTLS backend rejects connections when the proxy has no client cert.
func TestIntegration_MTLSBackend_RejectsWithoutClientCert(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	addr := startTLSServer(t, dockerMock(), serverCert, caPool)

	// No client cert — should fail.
	b := backend{
		network:   "tcp",
		address:   addr,
		tlsConfig: &tls.Config{RootCAs: caPool},
	}
	proxy := newProxy(b)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1.45/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (backend should reject missing client cert)", resp.StatusCode)
	}
}

// TestIntegration_UpgradeThroughTLSBackend verifies that HTTP upgrade
// (docker exec/attach) works through a TLS backend.
func TestIntegration_UpgradeThroughTLSBackend(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	// Mock upgrade server: hijack and echo.
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			http.Error(w, "expected upgrade", 400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tcp\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()

		line, err := buf.ReadString('\n')
		if err != nil {
			return
		}
		buf.WriteString("echo:" + line)
		buf.Flush()
	})

	addr := startTLSServer(t, mock, serverCert, nil)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	b := backend{
		network:   "tcp",
		address:   addr,
		tlsConfig: &tls.Config{RootCAs: caPool},
	}
	proxy := newProxy(b)
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "POST /v1.45/exec/abc123/start HTTP/1.1\r\n" +
		"Host: docker\r\n" +
		"Upgrade: tcp\r\n" +
		"Connection: Upgrade\r\n" +
		"\r\n"
	fmt.Fprint(conn, req)

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101, got: %s", statusLine)
	}

	// Consume response headers.
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	fmt.Fprint(conn, "hello\n")
	reply, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "echo:hello\n" {
		t.Errorf("reply = %q, want %q", reply, "echo:hello\n")
	}
}

// TestBuildBackendTLS_FromFiles verifies the buildBackendTLS function
// loads CA, cert, and key files correctly.
func TestBuildBackendTLS_FromFiles(t *testing.T) {
	ca := newTestCA(t)
	clientCert := ca.issueCert(t, clientTemplate())

	caPath := writePEM(t, ca.certPEM, "ca.pem")
	certPath, keyPath := writeCertAndKey(t, clientCert, "client")

	cfg, err := buildBackendTLS(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

// TestBuildBackendTLS_Empty returns nil when no files are provided.
func TestBuildBackendTLS_Empty(t *testing.T) {
	cfg, err := buildBackendTLS("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Error("expected nil config when no TLS files provided")
	}
}

// TestBuildBackendTLS_MismatchedCertKey errors when only cert or only key is set.
func TestBuildBackendTLS_MismatchedCertKey(t *testing.T) {
	_, err := buildBackendTLS("", "/some/cert.pem", "")
	if err == nil {
		t.Error("expected error for cert without key")
	}
	_, err = buildBackendTLS("", "", "/some/key.pem")
	if err == nil {
		t.Error("expected error for key without cert")
	}
}

// TestBuildBackendTLS_CAOnly enables TLS with server verification only (no client cert).
func TestBuildBackendTLS_CAOnly(t *testing.T) {
	ca := newTestCA(t)
	caPath := writePEM(t, ca.certPEM, "ca.pem")

	cfg, err := buildBackendTLS(caPath, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
	if len(cfg.Certificates) != 0 {
		t.Error("expected no client certificates")
	}
}
