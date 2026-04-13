package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"swarm-rbac-proxy/internal/api"
	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/config"
	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
)

func l() *proxylog.ProxyLogger { return proxylog.L().With("component", "proxy") }

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
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := b.dial()
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(30 * time.Second)
			}
			return conn, nil
		},
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
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
	l().Debugw("upgrade request", "path", r.URL.Path, "method", r.Method)

	hj, ok := w.(http.Hijacker)
	if !ok {
		l().Errorw("hijack not supported")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	backConn, err := b.dial()
	if err != nil {
		l().Errorw("backend dial failed", "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer backConn.Close()

	// Write the original request verbatim to the backend.
	if err := r.Write(backConn); err != nil {
		l().Errorw("backend write failed", "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Hijack the client connection and bidirectionally copy bytes.
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		l().Errorw("client hijack failed", "error", err)
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
	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		// Logger not ready yet; fall back to stderr.
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	proxylog.Init(cfg.Env, cfg.LogLevel)
	defer proxylog.Sync()

	listenAddr := cfg.Listen
	if listenAddr == "" {
		listenAddr = ":2375"
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			listenAddr = ":2376"
		}
	}

	var raw string
	switch {
	case cfg.DockerURL != "" && cfg.DockerSocket != "":
		l().Fatalw("mutually exclusive config", "error", "docker_url and docker_socket cannot both be set")
	case cfg.DockerURL != "":
		raw = cfg.DockerURL
	case cfg.DockerSocket != "":
		raw = "unix://" + cfg.DockerSocket
	default:
		raw = "unix:///var/run/docker.sock"
	}

	b, err := parseBackend(raw)
	if err != nil {
		l().Fatalw("invalid docker backend", "error", err)
	}

	b.tlsConfig, err = buildBackendTLS(cfg.DockerTLSCA, cfg.DockerTLSCert, cfg.DockerTLSKey)
	if err != nil {
		l().Fatalw("invalid backend TLS config", "error", err)
	}

	var userStore store.UserStore
	switch cfg.Store {
	case "sqlite":
		sq, err := store.NewSQLiteStore(context.Background(), cfg.DatabasePath)
		if err != nil {
			l().Fatalw("sqlite store init failed", "error", err)
		}
		defer sq.Close()
		userStore = sq
	case "memory":
		userStore = store.NewMemoryStore()
	case "postgres":
		if cfg.DatabaseURL == "" {
			l().Fatalw("missing required config", "error", "database_url is required when store=postgres")
		}
		pg, err := store.NewPostgresStore(context.Background(), cfg.DatabaseURL)
		if err != nil {
			l().Fatalw("postgres store init failed", "error", err)
		}
		defer pg.Close()
		userStore = pg
	default:
		l().Fatalw("unknown store type", "store", cfg.Store)
	}

	if cfg.SeedUsername != "" {
		seedRole := cfg.SeedRole
		if seedRole == "" {
			seedRole = "user"
		}
		u := &store.User{Username: cfg.SeedUsername, Role: seedRole}
		if err := userStore.CreateUser(context.Background(), u); err != nil {
			if errors.Is(err, store.ErrUsernameExists) {
				l().Infow("seed user already exists", "username", cfg.SeedUsername)
			} else {
				l().Fatalw("seed user creation failed", "error", err)
			}
		} else {
			l().Infow("seed user created", "username", cfg.SeedUsername, "role", seedRole, "id", u.ID)
		}
	}

	var ca *certauth.CA
	if cfg.TLSClientCAKey != "" {
		if cfg.TLSClientCA == "" {
			l().Fatalw("tls_client_ca_key is set but tls_client_ca is not")
		}
		ca, err = certauth.LoadCA(cfg.TLSClientCA, cfg.TLSClientCAKey)
		if err != nil {
			l().Fatalw("load client CA for cert issuance", "error", err)
		}
		l().Infow("client certificate auto-generation enabled")
	}

	if cfg.AdminToken == "" {
		l().Warnw("admin_token not set, management API is unauthenticated")
	}

	// Determine protected stack name (auto-detect or explicit override).
	protectedStack := cfg.ProtectedStack
	socketPath := ""
	if b.network == "unix" {
		socketPath = b.address
	}
	if protectedStack == "" && socketPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		detected, detectErr := api.DetectStackName(ctx, socketPath)
		cancel()
		if detectErr != nil {
			l().Warnw("stack self-detection failed, resource guard disabled", "error", detectErr)
		} else {
			protectedStack = detected
			l().Infow("detected protected stack", "stack", protectedStack)
		}
	}

	guard := api.NewResourceGuard(protectedStack, socketPath)
	if protectedStack != "" {
		l().Infow("resource guard enabled", "protected_stack", protectedStack)
	}

	userHandler := api.NewUserHandler(userStore, ca)
	onboardHandler := api.NewOnboardHandler(userStore, ca, cfg.ExternalURL)

	var proxyAuth func(http.Handler) http.Handler
	if cfg.TLSClientCA != "" {
		proxyAuth = func(next http.Handler) http.Handler {
			return api.RequireClientCert(userStore, next)
		}
	} else {
		proxyAuth = func(next http.Handler) http.Handler { return next }
	}

	var agentProxy http.Handler
	if cfg.AgentProxyURL != "" {
		agentBE, err := parseBackend(cfg.AgentProxyURL)
		if err != nil {
			l().Fatalw("parse agent proxy URL", "error", err)
		}
		agentProxy = newProxy(agentBE)
		l().Infow("agent proxy forwarding enabled", "url", cfg.AgentProxyURL)
	}

	dockerProxy := guard.Wrap(newProxy(b))

	// registerRoutes sets up the mux with the given auth wrapper for proxy
	// routes. wrapExec applies exec access control — RequireAdminForExec on
	// the external listener, no-op on the internal listener (where localhost
	// exec is always allowed).
	registerRoutes := func(mux *http.ServeMux, wrapProxy, wrapExec func(http.Handler) http.Handler) {
		mux.Handle("/api/v1/users", api.RequireToken(cfg.AdminToken, userHandler))
		mux.Handle("DELETE /api/v1/users/{username}", api.RequireToken(cfg.AdminToken, http.HandlerFunc(userHandler.Delete)))
		mux.Handle("GET /api/v1/onboard/{token}", onboardHandler)
		if agentProxy != nil {
			mux.Handle("/v1/", wrapProxy(wrapExec(agentProxy)))
		}
		mux.Handle("/", wrapProxy(wrapExec(dockerProxy)))
	}

	l().Infow("proxy listening", "addr", listenAddr, "backend_network", b.network, "backend_addr", b.address)
	if b.tlsConfig != nil {
		l().Infow("backend TLS enabled")
	}

	// Internal listener (plain TCP, no mTLS) — for admin access from localhost.
	if cfg.InternalListen != "" {
		internalMux := http.NewServeMux()
		noAuth := func(next http.Handler) http.Handler { return next }
		noExecGuard := func(next http.Handler) http.Handler { return next }
		registerRoutes(internalMux, noAuth, noExecGuard)
		go func() {
			l().Infow("internal listener starting", "addr", cfg.InternalListen)
			if err := http.ListenAndServe(cfg.InternalListen, internalMux); err != nil {
				l().Fatalw("internal listener exited", "error", err)
			}
		}()
	}

	// External listener.
	externalMux := http.NewServeMux()
	registerRoutes(externalMux, proxyAuth, api.RequireAdminForExec)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		l().Infow("frontend TLS enabled", "cert", cfg.TLSCert, "key", cfg.TLSKey)

		tlsCfg := &tls.Config{}
		if cfg.TLSClientCA != "" {
			caPEM, err := os.ReadFile(cfg.TLSClientCA)
			if err != nil {
				l().Fatalw("read client CA", "error", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				l().Fatalw("no valid certs in client CA file", "path", cfg.TLSClientCA)
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			l().Infow("frontend mTLS enabled (optional client cert)", "client_ca", cfg.TLSClientCA)
		}

		srv := &http.Server{
			Addr:      listenAddr,
			Handler:   externalMux,
			TLSConfig: tlsCfg,
		}
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			l().Fatalw("server exited", "error", err)
		}
	} else {
		if cfg.TLSClientCA != "" {
			l().Warnw("tls_client_ca is set but tls_cert/tls_key are not; mTLS will not be enabled")
		}
		if err := http.ListenAndServe(listenAddr, externalMux); err != nil {
			l().Fatalw("server exited", "error", err)
		}
	}
}
