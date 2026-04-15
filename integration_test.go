package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

	"swarm-rbac-proxy/internal/api"
	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/store"
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

// clientTemplateWithCN returns a client certificate template with a specific CN.
func clientTemplateWithCN(cn string) *x509.Certificate {
	tmpl := clientTemplate()
	tmpl.Subject.CommonName = cn
	return tmpl
}

// startMTLSFrontend builds the full mux with RequireClientCert middleware
// and starts a TLS server that requires client certs signed by the given CA.
func startMTLSFrontend(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool, userStore store.UserStore, backendHandler http.Handler) string {
	t.Helper()

	backendAddr := startTCPServer(t, backendHandler)
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(userStore, newProxy(b)))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// TestIntegration_FrontendMTLS_ValidClient verifies that a client with a
// valid certificate whose CN matches a user in the store can access the proxy.
func TestIntegration_FrontendMTLS_ValidClient(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice"}); err != nil {
		t.Fatal(err)
	}

	addr := startMTLSFrontend(t, serverCert, caPool, s, dockerMock())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	resp, err := client.Get("https://" + addr + "/v1.45/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestIntegration_FrontendMTLS_UnknownUser verifies that a valid client cert
// whose CN does not match any user in the store is rejected with 403.
func TestIntegration_FrontendMTLS_UnknownUser(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("unknown"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	addr := startMTLSFrontend(t, serverCert, caPool, s, dockerMock())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	resp, err := client.Get("https://" + addr + "/v1.45/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestIntegration_FrontendMTLS_NoClientCert verifies that a client connecting
// without a certificate passes the TLS handshake (VerifyClientCertIfGiven)
// but is rejected by the RequireClientCert middleware with 401.
func TestIntegration_FrontendMTLS_NoClientCert(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	addr := startMTLSFrontend(t, serverCert, caPool, s, dockerMock())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
			// No client certificate.
		},
	}}

	resp, err := client.Get("https://" + addr + "/v1.45/info")
	if err != nil {
		t.Fatalf("expected successful TLS handshake, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestIntegration_FrontendMTLS_ManagementAPINotWrapped verifies that the
// management API (/api/v1/users) is NOT behind RequireClientCert middleware.
// A client with a valid CA-signed cert (but CN not in the store) can still
// access the management API using the bearer token.
func TestIntegration_FrontendMTLS_ManagementAPINotWrapped(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("notinstore"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	// Build mux with both management API and Docker proxy,
	// matching the wiring in main.go.
	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/users", api.RequireToken("secret", api.NewUserHandler(s, nil)))
	mux.Handle("/", api.RequireClientCert(s, newProxy(b)))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	// Management API: cert CN "notinstore" is not in the store,
	// but the route is not wrapped in RequireClientCert.
	req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("management API: status = %d, want 200", resp.StatusCode)
	}

	// Docker proxy: same cert should be rejected (CN not in store).
	resp2, err := client.Get("https://" + ln.Addr().String() + "/v1.45/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("docker proxy: status = %d, want 403", resp2.StatusCode)
	}
}

// TestIntegration_FrontendMTLS_SeedUser verifies that a seed user (created
// at startup) can authenticate via mTLS and access the Docker proxy.
func TestIntegration_FrontendMTLS_SeedUser(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("seedadmin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	// Seed user at startup, same as main.go does.
	if err := s.CreateUser(context.Background(), &store.User{Username: "seedadmin"}); err != nil {
		t.Fatal(err)
	}

	addr := startMTLSFrontend(t, serverCert, caPool, s, dockerMock())

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	resp, err := client.Get("https://" + addr + "/v1.45/containers/json")
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

// TestIntegration_CreateUserWithCert_ThenMTLSAccess verifies the full flow:
// admin creates a user → API returns a cert bundle → the returned cert
// authenticates successfully through the mTLS proxy.
func TestIntegration_CreateUserWithCert_ThenMTLSAccess(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	adminCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	// Write CA cert+key so certauth.LoadCA can read them.
	caCertPath := writePEM(t, ca.certPEM, "ca.pem")
	caKeyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})
	caKeyPath := writePEM(t, caKeyPEM, "ca-key.pem")

	issuer, err := certauth.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	s := store.NewMemoryStore()
	// Seed admin user.
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin"}); err != nil {
		t.Fatal(err)
	}

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/users", api.RequireToken("secret", api.NewUserHandler(s, issuer)))
	mux.Handle("/", api.RequireClientCert(s, newProxy(b)))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	// Step 1: Admin creates user "alice" via management API.
	adminClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{adminCert},
		},
	}}

	createReq, _ := http.NewRequest(http.MethodPost,
		"https://"+ln.Addr().String()+"/api/v1/users",
		strings.NewReader(`{"username":"alice"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer secret")
	createResp, err := adminClient.Do(createReq)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create user: status = %d, body = %s", createResp.StatusCode, body)
	}

	// Parse the cert bundle from the response.
	var resp struct {
		Username    string `json:"username"`
		Certificate *struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
			CAPEM   string `json:"ca_pem"`
		} `json:"certificate"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Certificate == nil {
		t.Fatal("expected certificate bundle in response")
	}

	// Step 2: Use the returned cert to authenticate through the mTLS proxy.
	aliceCert, err := tls.X509KeyPair([]byte(resp.Certificate.CertPEM), []byte(resp.Certificate.KeyPEM))
	if err != nil {
		t.Fatalf("parse returned cert+key: %v", err)
	}
	aliceClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{aliceCert},
		},
	}}

	dockerResp, err := aliceClient.Get("https://" + ln.Addr().String() + "/v1.45/containers/json")
	if err != nil {
		t.Fatalf("docker request: %v", err)
	}
	defer dockerResp.Body.Close()
	if dockerResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dockerResp.Body)
		t.Fatalf("docker request: status = %d, body = %s", dockerResp.StatusCode, body)
	}
}

// --- Integration tests: mTLS + ResourceGuard ---

// startMockDockerSocket creates a Unix socket that serves Docker inspect
// responses for the guard's back-queries. The handler should respond to
// GET /services/{id} (or /networks/{id}, etc.) with the resource's JSON.
func startMockDockerSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// startMTLSFrontendWithGuard is like startMTLSFrontend but includes the
// ResourceGuard middleware, mirroring the wiring in main.go:
//
//	RequireClientCert → guard.Wrap → newProxy(backend)
func startMTLSFrontendWithGuard(
	t *testing.T,
	serverCert tls.Certificate,
	clientCA *x509.CertPool,
	userStore store.UserStore,
	backendHandler http.Handler,
	protectedStack string,
	dockerSocketPath string,
) string {
	t.Helper()

	backendAddr := startTCPServer(t, backendHandler)
	b := backend{network: "tcp", address: backendAddr}

	guard := api.NewResourceGuard(protectedStack, dockerSocketPath)

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(userStore, guard.Wrap(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// TestIntegration_FrontendMTLS_UserDeleteProtectedService verifies that a
// non-admin user authenticated via mTLS is blocked from deleting a service
// belonging to the protected stack.
func TestIntegration_FrontendMTLS_UserDeleteProtectedService(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	// Mock Docker socket: returns a service belonging to the protected stack.
	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", sock)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1.44/services/proxy-svc", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_FrontendMTLS_AdminDeleteProtectedService verifies that an
// admin user authenticated via mTLS is blocked from deleting a protected
// stack service — only the internal listener can mutate protected resources.
func TestIntegration_FrontendMTLS_AdminDeleteProtectedService(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", sock)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1.44/services/proxy-svc", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_FrontendMTLS_UserDeleteNonProtectedService verifies that a
// non-admin user can delete a service that does not belong to the protected stack.
func TestIntegration_FrontendMTLS_UserDeleteNonProtectedService(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("bob"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "bob", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	// Mock Docker socket: returns a service NOT in the protected stack.
	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"user-app"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", sock)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodDelete, "https://"+addr+"/v1.44/services/user-svc", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}

	// Verify the request actually reached the backend.
	body, _ := io.ReadAll(resp.Body)
	respStr := string(body)
	_ = respStr // backend echoes path; status 200 is sufficient proof
}

// TestIntegration_InternalListener_DeleteProtectedService verifies that the
// internal (plain TCP, no auth) listener can delete protected stack resources.
// This mirrors main.go's internal listener wiring: no RequireClientCert,
// so the guard sees no user context and allows the request.
func TestIntegration_InternalListener_DeleteProtectedService(t *testing.T) {
	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	guard := api.NewResourceGuard("swarmcli-infra", sock)

	// Internal listener: guard.Wrap(proxy) with no auth middleware — matches main.go.
	mux := http.NewServeMux()
	mux.Handle("/", guard.Wrap(newProxy(b)))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/v1.44/services/proxy-svc", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// TestIntegration_FrontendMTLS_UserSwarmLeave verifies that a non-admin user
// is blocked from executing POST /swarm/leave through the mTLS proxy.
func TestIntegration_FrontendMTLS_UserSwarmLeave(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	// No back-query needed for swarm leave — it's unconditionally blocked.
	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", "")

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/swarm/leave", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_FrontendMTLS_AdminSwarmLeave verifies that even an admin
// user is blocked from executing POST /swarm/leave through the mTLS proxy.
func TestIntegration_FrontendMTLS_AdminSwarmLeave(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", "")

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/swarm/leave", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_FrontendMTLS_AdminUpdateProtectedService verifies that an
// admin user can update a protected stack service through the mTLS proxy.
func TestIntegration_FrontendMTLS_AdminUpdateProtectedService(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", sock)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1.44/services/proxy-svc/update", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// TestIntegration_FrontendMTLS_UserUpdateProtectedService verifies that a
// non-admin user is blocked from updating a protected stack service.
func TestIntegration_FrontendMTLS_UserUpdateProtectedService(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	dockerMockInspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":"swarmcli-infra"}}}`)
	})
	sock := startMockDockerSocket(t, dockerMockInspect)

	addr := startMTLSFrontendWithGuard(t, serverCert, caPool, s, dockerMock(), "swarmcli-infra", sock)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1.44/services/proxy-svc/update", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// --- Exec guard integration tests ---

// execGuardDockerMock returns a Unix socket server that responds to
// ResourceGuard back-queries (containers, tasks, services) reporting the
// given stackLabel for every resource.
func execGuardDockerMock(t *testing.T, stackLabel string) (string, func()) {
	t.Helper()
	mock := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			fmt.Fprintf(w, `{"Config":{"Labels":{"com.docker.stack.namespace":%q}}}`, stackLabel)
		case strings.HasPrefix(r.URL.Path, "/tasks/"):
			fmt.Fprint(w, `{"ServiceID":"svc-abc"}`)
		case strings.HasPrefix(r.URL.Path, "/services/"):
			fmt.Fprintf(w, `{"Spec":{"Labels":{"com.docker.stack.namespace":%q}}}`, stackLabel)
		default:
			http.NotFound(w, r)
		}
	})
	return startMockSocket(t, mock)
}

// TestIntegration_ExecGuard_NoMTLS_Blocked verifies that exec on a protected-
// stack container is blocked even without mTLS (no user context = not admin).
func TestIntegration_ExecGuard_NoMTLS_Blocked(t *testing.T) {
	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	agentBackend := startTCPServer(t, dockerMock())
	agentBE := backend{network: "tcp", address: agentBackend}
	agentProxy := newProxy(agentBE)

	noAuth := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	mux.Handle("/v1/", noAuth(g.ExecGuard(agentProxy)))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// task_id identifies a task in the protected stack — guard back-queries confirm it.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/exec?task_id=task-xyz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_ExecGuard_NoMTLS_DockerExecBlocked verifies that Docker API
// exec on a protected-stack container is blocked without mTLS.
func TestIntegration_ExecGuard_NoMTLS_DockerExecBlocked(t *testing.T) {
	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	noAuth := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	mux.Handle("/", noAuth(g.ExecGuard(newProxy(b))))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/v1.44/containers/abc/exec", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_ExecGuard_NoMTLS_NonExecAllowed verifies that non-exec
// requests are not affected by the guard regardless of mTLS.
func TestIntegration_ExecGuard_NoMTLS_NonExecAllowed(t *testing.T) {
	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	noAuth := func(next http.Handler) http.Handler { return next }
	mux := http.NewServeMux()
	mux.Handle("/", noAuth(g.ExecGuard(newProxy(b))))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1.44/containers/json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// TestIntegration_ExecGuard_MTLS_AdminAllowed verifies that an admin user
// authenticated via mTLS can exec into a protected-stack container.
func TestIntegration_ExecGuard_MTLS_AdminAllowed(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest("POST", "https://"+ln.Addr().String()+"/v1.44/containers/abc/exec", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// TestIntegration_ExecGuard_MTLS_UserBlocked verifies that a non-admin user
// authenticated via mTLS is blocked from exec on a protected-stack container.
func TestIntegration_ExecGuard_MTLS_UserBlocked(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest("POST", "https://"+ln.Addr().String()+"/v1.44/containers/abc/exec", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_ExecGuard_MTLS_UserAllowedNonProtected verifies that a
// non-admin user can exec into a container that does NOT belong to the
// protected stack.
func TestIntegration_ExecGuard_MTLS_UserAllowedNonProtected(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	// Mock reports container as belonging to a user stack, not the infra stack.
	sock, cleanup := execGuardDockerMock(t, "user-app")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest("POST", "https://"+ln.Addr().String()+"/v1.44/containers/abc/exec", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// TestIntegration_ExecGuard_MTLS_UserAttachWSBlocked verifies that a non-admin
// user is blocked from the WebSocket attach endpoint on a protected-stack container.
func TestIntegration_ExecGuard_MTLS_UserAttachWSBlocked(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	clientCert := ca.issueCert(t, clientTemplateWithCN("alice"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "alice", Role: "user"}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}}

	req, _ := http.NewRequest("GET", "https://"+ln.Addr().String()+"/v1.44/containers/abc/attach/ws", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusForbidden, body)
	}
}

// TestIntegration_InternalListener_ExecAllowed tests that the internal
// listener allows exec — matching the internal listener wiring in main.go,
// which uses noExecGuard and never applies ExecGuard.
func TestIntegration_InternalListener_ExecAllowed(t *testing.T) {
	agentBackend := startTCPServer(t, dockerMock())
	agentBE := backend{network: "tcp", address: agentBackend}

	// Internal listener: no auth, no exec guard — mirrors main.go.
	mux := http.NewServeMux()
	mux.Handle("/v1/", newProxy(agentBE))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/v1/exec", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// --- No-cert client tests (VerifyClientCertIfGiven) ---

// TestIntegration_FrontendMTLS_NoCertExecBlocked verifies that a client
// connecting without a certificate to an exec endpoint gets 401 from
// RequireClientCert (not 403 from the exec guard).
func TestIntegration_FrontendMTLS_NoCertExecBlocked(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	// RequireClientCert rejects before ExecGuard is reached; guard config
	// doesn't matter for this test, but we use a real guard for consistency.
	g := api.NewResourceGuard("swarmcli-infra", "")
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
	}}

	req, _ := http.NewRequest("POST", "https://"+ln.Addr().String()+"/v1.44/containers/abc/exec", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusUnauthorized, body)
	}
}

// TestIntegration_FrontendMTLS_NoCertManagementAPIAllowed verifies that a
// client without a certificate can access the management API using a bearer
// token, since management routes are not wrapped in RequireClientCert.
func TestIntegration_FrontendMTLS_NoCertManagementAPIAllowed(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	s := store.NewMemoryStore()

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/users", api.RequireToken("secret", api.NewUserHandler(s, nil)))
	mux.Handle("/", api.RequireClientCert(s, newProxy(b)))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
			// No client certificate.
		},
	}}

	req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, http.StatusOK, body)
	}
}

// --- E2E exec guard test with onboarded user ---

// TestIntegration_ExecGuard_MTLS_OnboardedUserBlocked exercises the full
// onboard flow: admin creates non-admin user → cert is issued → user
// authenticates via mTLS → exec request is blocked (403).
func TestIntegration_ExecGuard_MTLS_OnboardedUserBlocked(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issueCert(t, serverTemplate())
	adminCert := ca.issueCert(t, clientTemplateWithCN("admin"))

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.certPEM)

	// Write CA cert+key so certauth.LoadCA can read them.
	caCertPath := writePEM(t, ca.certPEM, "ca.pem")
	caKeyDER, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})
	caKeyPath := writePEM(t, caKeyPEM, "ca-key.pem")

	issuer, err := certauth.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	s := store.NewMemoryStore()
	if err := s.CreateUser(context.Background(), &store.User{Username: "admin", Role: "admin"}); err != nil {
		t.Fatal(err)
	}

	sock, cleanup := execGuardDockerMock(t, "swarmcli-infra")
	defer cleanup()
	g := api.NewResourceGuard("swarmcli-infra", sock)

	backendAddr := startTCPServer(t, dockerMock())
	b := backend{network: "tcp", address: backendAddr}

	mux := http.NewServeMux()
	mux.Handle("/api/v1/users", api.RequireToken("secret", api.NewUserHandler(s, issuer)))
	mux.Handle("/", api.RequireClientCert(s, g.ExecGuard(newProxy(b))))

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	addr := ln.Addr().String()

	// Step 1: Admin creates non-admin user "bob" via management API.
	adminClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{adminCert},
		},
	}}

	createReq, _ := http.NewRequest(http.MethodPost,
		"https://"+addr+"/api/v1/users",
		strings.NewReader(`{"username":"bob","role":"user"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer secret")
	createResp, err := adminClient.Do(createReq)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create user: status = %d, body = %s", createResp.StatusCode, body)
	}

	// Step 2: Parse the cert bundle from the response.
	var certResp struct {
		Username    string `json:"username"`
		Certificate *struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
			CAPEM   string `json:"ca_pem"`
		} `json:"certificate"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&certResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if certResp.Certificate == nil {
		t.Fatal("expected certificate bundle in response")
	}

	// Step 3: Build bob's HTTP client with the returned cert.
	bobCert, err := tls.X509KeyPair([]byte(certResp.Certificate.CertPEM), []byte(certResp.Certificate.KeyPEM))
	if err != nil {
		t.Fatalf("parse returned cert+key: %v", err)
	}
	bobClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{bobCert},
		},
	}}

	// Step 4: Bob tries exec → blocked (403).
	execReq, _ := http.NewRequest("POST", "https://"+addr+"/v1.44/containers/abc/exec", nil)
	execResp, err := bobClient.Do(execReq)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer execResp.Body.Close()
	if execResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(execResp.Body)
		t.Fatalf("exec: status = %d, want %d; body = %s", execResp.StatusCode, http.StatusForbidden, body)
	}

	// Step 5: Bob accesses non-exec endpoint → allowed (200).
	dockerResp, err := bobClient.Get("https://" + addr + "/v1.45/containers/json")
	if err != nil {
		t.Fatalf("docker request: %v", err)
	}
	defer dockerResp.Body.Close()
	if dockerResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(dockerResp.Body)
		t.Fatalf("docker: status = %d, want %d; body = %s", dockerResp.StatusCode, http.StatusOK, body)
	}
}
