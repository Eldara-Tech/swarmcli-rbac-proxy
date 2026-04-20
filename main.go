// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

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
	"strings"
	"time"

	"swarm-rbac-proxy/internal/api"
	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/config"
	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
	"swarm-rbac-proxy/internal/version"
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

// warnIfUnqualifiedAgentManagerHost emits a warning when the agent-manager
// host is a bare single-label DNS name. Inside a Docker Swarm overlay, a
// bare name resolves via overlay DNS to *any* service of that name in the
// stack namespace; a colluding workload on the same overlay could register
// an `agent-manager` service and MITM admin exec traffic. Stack-qualified
// names like "swarmctl_agent-manager" scope resolution to the protected
// stack. See swarmcli-agent/docs/threat-model.md §T5.
func warnIfUnqualifiedAgentManagerHost(hostPort string) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if host == "" {
		return
	}
	// IP literal or FQDN (contains ".") or stack-qualified (contains "_") →
	// fine. Single-label short name → warn.
	if strings.ContainsAny(host, "._") {
		return
	}
	if ip := net.ParseIP(host); ip != nil {
		return
	}
	l().Warnw("PROXY_AGENT_MANAGER_URL uses an unqualified service name; "+
		"within a Docker Swarm overlay this is vulnerable to name-collision "+
		"MITM (see threat-model.md T5). Use a stack-qualified form like "+
		"tcp://<stack>_agent-manager:<port>", "host", host)
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

// idleConn wraps a net.Conn and resets the deadline on each read/write,
// providing an idle timeout that closes connections after inactivity.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
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

	idleTimeout := 1 * time.Hour
	client := &idleConn{clientConn, idleTimeout}
	back := &idleConn{backConn, idleTimeout}

	done := make(chan struct{})
	go func() {
		io.Copy(client, back)
		close(done)
	}()
	io.Copy(back, client)
	<-done
}

// errInsecureListener is returned by checkExternalListenerAuth when the
// external listener would not enforce authentication on the Docker proxy
// path.
var errInsecureListener = errors.New(
	"refusing to start: external listener does not enforce authentication on the Docker proxy path. " +
		"Configure mTLS by setting PROXY_TLS_CERT, PROXY_TLS_KEY, and PROXY_TLS_CLIENT_CA together — " +
		"PROXY_ADMIN_TOKEN alone protects only /api/v1/* routes and still lets any caller drive the Docker API. " +
		"To opt in to an insecure external listener (tests or fully network-isolated deployments only) " +
		"set PROXY_ALLOW_INSECURE=true",
)

// checkExternalListenerAuth refuses startup when the external listener would
// not enforce end-to-end authentication on the Docker proxy path. Effective
// mTLS on that path requires both PROXY_TLS_CERT and PROXY_TLS_CLIENT_CA:
// without the server cert, the listener cannot negotiate TLS and the
// RequireClientCert middleware is never attached; without the client CA,
// proxyAuth degrades to a no-op (main.go below) and identity is never
// checked. In either case any caller can drive the full Docker API,
// including host-mounting container creation (root-equivalent on the daemon
// host).
//
// PROXY_ADMIN_TOKEN alone is deliberately NOT sufficient: it only protects
// /api/v1/* (user CRUD, onboarding) via RequireToken. The Docker proxy
// passthrough at / and the agent-manager proxy at /v1/* do not use that middleware.
// An admin-token-only configuration leaves the Docker API wide open while
// simultaneously transmitting the token over plain HTTP, which is worse
// than "merely unauthenticated" because operators assume the token is
// protecting things.
//
// The allowInsecure flag is an explicit override for tests and deployments
// that rely on external network isolation (container overlays, bastioned
// hosts) for confidentiality. When set it logs a loud warning so the bypass
// is never silent.
func checkExternalListenerAuth(cfg config.Config, allowInsecure bool) error {
	if allowInsecure {
		return nil
	}
	if cfg.TLSCert == "" || cfg.TLSClientCA == "" {
		return errInsecureListener
	}
	return nil
}

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println(version.String())
			return
		}
	}

	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		// Logger not ready yet; fall back to stderr.
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	proxylog.Init(cfg.Env, cfg.LogLevel)
	defer proxylog.Sync()

	l().Infow("starting swarm-rbac-proxy", "version", version.Version, "commit", version.Commit)

	allowInsecure := os.Getenv("PROXY_ALLOW_INSECURE") == "true"
	if err := checkExternalListenerAuth(cfg, allowInsecure); err != nil {
		l().Fatalw("insecure listener configuration", "error", err)
	}
	if allowInsecure {
		l().Warnw("PROXY_ALLOW_INSECURE=true: external listener auth checks bypassed; ensure network-level isolation is in place")
	}

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
	var auditStore store.AuditStore
	switch cfg.Store {
	case "sqlite":
		sq, err := store.NewSQLiteStore(context.Background(), cfg.DatabasePath)
		if err != nil {
			l().Fatalw("sqlite store init failed", "error", err)
		}
		defer sq.Close()
		sq.SetTokenTTL(cfg.OnboardingTokenTTL)
		userStore = sq
		auditStore = sq
	case "memory":
		ms := store.NewMemoryStore()
		ms.SetTokenTTL(cfg.OnboardingTokenTTL)
		userStore = ms
		auditStore = ms
	case "postgres":
		if cfg.DatabaseURL == "" {
			l().Fatalw("missing required config", "error", "database_url is required when store=postgres")
		}
		pg, err := store.NewPostgresStore(context.Background(), cfg.DatabaseURL)
		if err != nil {
			l().Fatalw("postgres store init failed", "error", err)
		}
		defer pg.Close()
		pg.SetTokenTTL(cfg.OnboardingTokenTTL)
		userStore = pg
		auditStore = pg
	default:
		l().Fatalw("unknown store type", "store", cfg.Store)
	}
	if cfg.OnboardingTokenTTL > 0 {
		l().Infow("onboarding token TTL", "ttl", cfg.OnboardingTokenTTL)
	} else {
		l().Warnw("onboarding token TTL is disabled (PROXY_ONBOARDING_TOKEN_TTL=disabled); tokens never expire")
	}

	// T7b: refuse to start with an empty admin token when the user store
	// already contains admin-role identities. On a redeploy that drops
	// PROXY_ADMIN_TOKEN, the management API would otherwise open up because
	// RequireToken with an empty token short-circuits to pass-through
	// (api/auth.go:11-26). Fresh installs (no admins yet) still bootstrap.
	if cfg.AdminToken == "" {
		users, err := userStore.ListUsers(context.Background())
		if err != nil {
			l().Fatalw("list users for admin-token consistency check", "error", err)
		}
		for _, u := range users {
			if u.Role == "admin" {
				l().Fatalw("PROXY_ADMIN_TOKEN is empty but admins exist in the store; refusing to start",
					"admin_username", u.Username)
			}
		}
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
		if cfg.TLSCert != "" {
			l().Fatalw("admin_token must be set when TLS is enabled")
		}
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

	guard := api.NewResourceGuard(protectedStack, socketPath, auditStore)
	if protectedStack != "" {
		l().Infow("resource guard enabled", "protected_stack", protectedStack)
	}

	userHandler := api.NewUserHandler(userStore, ca, auditStore)
	onboardHandler := api.NewOnboardHandler(userStore, ca, cfg.ExternalURL, auditStore)

	var proxyAuth func(http.Handler) http.Handler
	if cfg.TLSClientCA != "" {
		proxyAuth = func(next http.Handler) http.Handler {
			return api.RequireClientCert(userStore, next)
		}
	} else {
		proxyAuth = func(next http.Handler) http.Handler { return next }
	}

	var agentManagerProxy http.Handler
	if cfg.AgentManagerURL != "" {
		agentBE, err := parseBackend(cfg.AgentManagerURL)
		if err != nil {
			l().Fatalw("parse agent-manager URL", "error", err)
		}
		warnIfUnqualifiedAgentManagerHost(agentBE.address)
		agentManagerProxy = newProxy(agentBE)
		l().Infow("agent-manager forwarding enabled", "url", cfg.AgentManagerURL)
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
		if agentManagerProxy != nil {
			mux.Handle("/v1/", wrapProxy(wrapExec(agentManagerProxy)))
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
		noExecGuard := func(next http.Handler) http.Handler { return next }
		registerRoutes(internalMux, api.MarkInternalRequest, noExecGuard)
		go func() {
			l().Infow("internal listener starting", "addr", cfg.InternalListen)
			srv := &http.Server{
				Addr:              cfg.InternalListen,
				Handler:           internalMux,
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil {
				l().Fatalw("internal listener exited", "error", err)
			}
		}()
	}

	// External listener.
	externalMux := http.NewServeMux()
	// Exec guard: active on the external listener; stack-aware — only exec on
	// protected-stack containers requires admin. Without mTLS no caller can prove
	// identity, so protected-stack exec is blocked (fail-closed); non-protected
	// exec may pass without identity verification.
	if cfg.AgentManagerURL != "" && cfg.TLSClientCA == "" {
		l().Warnw("exec guard active without mTLS: exec on protected stack will be blocked; non-protected exec may pass without identity; use PROXY_INTERNAL_LISTEN for local exec access")
	}
	registerRoutes(externalMux, proxyAuth, guard.ExecGuard)

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
			Addr:              listenAddr,
			Handler:           externalMux,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			l().Fatalw("server exited", "error", err)
		}
	} else {
		if cfg.TLSClientCA != "" {
			l().Warnw("tls_client_ca is set but tls_cert/tls_key are not; mTLS will not be enabled")
		}
		srv := &http.Server{
			Addr:              listenAddr,
			Handler:           externalMux,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if err := srv.ListenAndServe(); err != nil {
			l().Fatalw("server exited", "error", err)
		}
	}
}
