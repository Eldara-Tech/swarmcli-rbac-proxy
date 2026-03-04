package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// backend represents a Docker daemon endpoint (Unix socket or TCP).
type backend struct {
	network   string      // "unix" or "tcp"
	address   string      // socket path or host:port
	tlsConfig *tls.Config // non-nil enables TLS for backend connections
}

func (b backend) dial() (net.Conn, error) {
	if b.tlsConfig != nil {
		return tls.Dial(b.network, b.address, b.tlsConfig)
	}
	return net.Dial(b.network, b.address)
}

// buildBackendTLS constructs a tls.Config from optional CA, cert, and key files.
// Any non-empty parameter enables TLS on the backend connection.
func buildBackendTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && caFile == "" {
		return nil, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("PROXY_DOCKER_TLS_CERT and PROXY_DOCKER_TLS_KEY must both be set or both be empty")
	}

	cfg := &tls.Config{}

	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certificates in CA file %s", caFile)
		}
		cfg.RootCAs = pool
	}

	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// parseBackend parses a Docker endpoint URL into a backend.
// Supported forms: "unix:///path", "tcp://host:port", or a bare "/path" (unix).
func parseBackend(raw string) (backend, error) {
	if raw == "" {
		return backend{}, fmt.Errorf("empty docker URL")
	}
	// Bare path → unix socket.
	if raw[0] == '/' {
		return backend{network: "unix", address: raw}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return backend{}, fmt.Errorf("invalid docker URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "unix":
		return backend{network: "unix", address: u.Path}, nil
	case "tcp":
		return backend{network: "tcp", address: u.Host}, nil
	default:
		return backend{}, fmt.Errorf("unsupported scheme %q in %q (expected unix or tcp)", u.Scheme, raw)
	}
}

// newProxy builds the reverse-proxy handler for the given Docker backend.
func newProxy(b backend) http.Handler {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return b.dial()
		},
	}

	target := &url.URL{Scheme: "http", Host: "docker"}
	if b.network == "tcp" {
		target.Host = b.address
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if b.network == "unix" {
				pr.Out.Host = "docker"
			}
		},
		Transport: transport,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			handleUpgrade(w, r, b)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// handleUpgrade proxies HTTP upgrade (hijack) requests used by
// docker exec, docker attach, and raw streaming endpoints.
func handleUpgrade(w http.ResponseWriter, r *http.Request, b backend) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	backConn, err := b.dial()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer backConn.Close()

	// Write the original request verbatim to the backend.
	if err := r.Write(backConn); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Hijack the client connection and bidirectionally copy bytes.
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Flush any buffered data from the hijacked reader first.
	if n := clientBuf.Reader.Buffered(); n > 0 {
		buffered := make([]byte, n)
		if _, err := clientBuf.Read(buffered); err != nil {
			return
		}
		if _, err := backConn.Write(buffered); err != nil {
			return
		}
	}

	done := make(chan struct{})
	go func() {
		io.Copy(clientConn, backConn)
		close(done)
	}()
	io.Copy(backConn, clientConn)
	<-done
}

func main() {
	tlsCert := os.Getenv("PROXY_TLS_CERT")
	tlsKey := os.Getenv("PROXY_TLS_KEY")

	defaultPort := ":2375"
	if tlsCert != "" && tlsKey != "" {
		defaultPort = ":2376"
	}
	listenAddr := env("PROXY_LISTEN", defaultPort)

	dockerURL := os.Getenv("PROXY_DOCKER_URL")
	dockerSocket := os.Getenv("PROXY_DOCKER_SOCKET")

	var raw string
	switch {
	case dockerURL != "" && dockerSocket != "":
		log.Fatal("PROXY_DOCKER_URL and PROXY_DOCKER_SOCKET are mutually exclusive, set only one")
	case dockerURL != "":
		raw = dockerURL
	case dockerSocket != "":
		raw = "unix://" + dockerSocket
	default:
		raw = "unix:///var/run/docker.sock"
	}

	b, err := parseBackend(raw)
	if err != nil {
		log.Fatalf("invalid docker backend: %v", err)
	}

	b.tlsConfig, err = buildBackendTLS(
		os.Getenv("PROXY_DOCKER_TLS_CA"),
		os.Getenv("PROXY_DOCKER_TLS_CERT"),
		os.Getenv("PROXY_DOCKER_TLS_KEY"),
	)
	if err != nil {
		log.Fatalf("invalid backend TLS config: %v", err)
	}

	handler := newProxy(b)

	log.Printf("proxy listening on %s → %s://%s", listenAddr, b.network, b.address)
	if b.tlsConfig != nil {
		log.Printf("backend TLS enabled")
	}
	if tlsCert != "" && tlsKey != "" {
		log.Printf("frontend TLS enabled (cert=%s key=%s)", tlsCert, tlsKey)
		log.Fatal(http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, handler))
	} else {
		log.Fatal(http.ListenAndServe(listenAddr, handler))
	}
}
