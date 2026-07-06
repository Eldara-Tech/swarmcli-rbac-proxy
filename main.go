// SPDX-License-Identifier: AGPL-3.0-only
// Copyright © 2026 Eldara Tech

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"swarm-rbac-proxy/internal/backup"
	"swarm-rbac-proxy/internal/certauth"
	"swarm-rbac-proxy/internal/config"
	proxylog "swarm-rbac-proxy/internal/log"
	"swarm-rbac-proxy/internal/store"
	"swarm-rbac-proxy/internal/version"
)

func l() *proxylog.ProxyLogger { return proxylog.L().With("component", "proxy") }

// internalServerName is the SAN the bootstrap-issued internal-server cert
// carries for the agent-manager. It is fixed and stack-name-independent
// (the cert is generated without knowing the stack name), so the proxy must
// verify against this name rather than the stack-qualified dial host such
// as "<stack>_agent-manager". Must stay in lockstep with
// swarmcli-be/bootstrap/tls.go internalServerSANs and the agent-manager's
// own ServerName pin.
const internalServerName = "swarmcli-agent-manager"

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

// buildBundleTLS constructs a backend tls.Config from a single consolidated PEM
// file (client cert + key + CA cert) — the `internal-client` Docker secret.
// The keypair is read with X509KeyPair (the leaf is the first CERTIFICATE
// block) and the CA pool from the same bytes; the leaf also lands in the pool
// harmlessly, as it is not a CA.
func buildBundleTLS(bundleFile string) (*tls.Config, error) {
	pemBytes, err := os.ReadFile(bundleFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS bundle %s: %w", bundleFile, err)
	}
	cert, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("load keypair from bundle %s: %w", bundleFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no CA certificate in bundle %s", bundleFile)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool}, nil
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
	case "wss", "https":
		// TLS-secured TCP backend (used for the agent-manager hop). The
		// caller attaches the mutual-TLS client config; here we only
		// resolve the transport address.
		return backend{network: "tcp", address: u.Host}, nil
	default:
		return backend{}, fmt.Errorf("unsupported scheme %q in %q (expected unix, tcp, wss, or https)", u.Scheme, raw)
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

// mountControlPlane registers the proxy's control-plane routes under the
// reserved /_swc/ namespace, and only on the internal (loopback, no-auth)
// listener — the same trusted admin path used for stack deploy/exec. The whole
// namespace is deliberately absent from the external mTLS mux: these endpoints
// are unauthenticated.
//
// Real Docker API traffic never uses /_swc/, so the namespace owns a branded
// 404 (handleControlNotFound) for any unknown control route instead of letting
// it fall through to the catch-all Docker proxy. That fall-through is what made
// a missing route indistinguishable from a genuine Docker 404 (PR #107): a
// stale build returns the daemon's own 404 with no hint that the route is
// simply absent. The endpoints:
//
//	GET   /_swc/version      build identity — its mere presence (200 here vs a
//	                         Docker 404 on an older build) is the "is this a
//	                         current build?" signal; fields add release detail.
//	*     /_swc/startbackup  DB-only backup trigger (never the CA); writes to the
//	                         proxy-data volume and returns the artifact filename.
//	                         Also served at /startbackup for back-compat.
//	*     /_swc/<unknown>    branded JSON 404, never proxied to Docker.
func mountControlPlane(mux *http.ServeMux, internal bool, userStore store.UserStore, audit store.AuditStore, dir string) {
	if !internal {
		return
	}
	backupHandler := newBackupHandler(userStore, audit, dir)
	mux.HandleFunc("/_swc/startbackup", backupHandler)
	mux.HandleFunc("/startbackup", backupHandler) // back-compat alias (pre-/_swc/ docs & muscle memory)
	mux.HandleFunc("GET /_swc/version", handleControlVersion)
	mux.HandleFunc("/_swc/", handleControlNotFound) // reserved namespace never falls through to Docker
}

// handleControlVersion reports the proxy build identity on the internal
// listener. Operators (and reviewers checking whether a feature is deployed)
// hit this first: a 200 means the binary is current enough to carry the /_swc/
// namespace, whereas a Docker 404 means a stale build that predates it.
func handleControlVersion(w http.ResponseWriter, _ *http.Request) {
	writeControlJSON(w, http.StatusOK, map[string]string{
		"version": version.Version,
		"commit":  version.Commit,
		"date":    version.Date,
	})
}

// handleControlNotFound answers any unregistered path under the reserved /_swc/
// namespace with a branded JSON 404, so a typo or a route the running build
// lacks is reported clearly instead of being forwarded to the Docker socket.
func handleControlNotFound(w http.ResponseWriter, r *http.Request) {
	writeControlJSON(w, http.StatusNotFound, map[string]string{
		"result": "error",
		"error":  "unknown control-plane route " + r.URL.Path + "; see GET /_swc/version",
	})
}

// newBackupHandler returns the backup-trigger handler for the internal listener
// (served at /_swc/startbackup and the /startbackup alias). It writes a DB-only
// logical backup (never the CA — that stays an opt-in, human-supervised CLI
// path) to dir and replies with the artifact filename. It accepts GET (so a
// bare `curl .../_swc/startbackup` works) and POST.
func newBackupHandler(userStore store.UserStore, audit store.AuditStore, dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeControlJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"result": "error", "error": "method not allowed; use GET or POST",
			})
			return
		}
		bs, ok := userStore.(store.BackupStore)
		if !ok {
			writeControlJSON(w, http.StatusNotImplemented, map[string]string{
				"result": "error", "error": "store backend does not support backup",
			})
			return
		}

		// includeTokens=false: the unauthenticated loopback trigger never embeds
		// bearer onboarding tokens (nor the CA) — those stay opt-in CLI paths.
		doc, err := backup.Create(r.Context(), bs, version.String(), time.Now().UTC(), false)
		if err != nil {
			l().Errorw("startbackup: export failed", "error", err)
			writeControlJSON(w, http.StatusInternalServerError, map[string]string{
				"result": "error", "error": err.Error(),
			})
			return
		}
		path, err := backup.WriteToDir(dir, doc)
		if err != nil {
			l().Errorw("startbackup: write failed", "error", err)
			writeControlJSON(w, http.StatusInternalServerError, map[string]string{
				"result": "error", "error": err.Error(),
			})
			return
		}

		_ = audit.RecordAudit(r.Context(), &store.AuditEntry{
			Actor: "internal", Action: store.AuditBackupExported,
			Resource: "backup", Status: "success",
			Detail:   fmt.Sprintf("users=%d audit=%d roles=%d bindings=%d ca=false tokens=false trigger=http", len(doc.Users), len(doc.Audit), len(doc.Roles), len(doc.Bindings)),
			SourceIP: requestIP(r),
		})

		l().Infow("backup written", "path", path, "users", len(doc.Users), "audit", len(doc.Audit))
		writeControlJSON(w, http.StatusOK, map[string]string{
			"result": "success",
			"file":   backup.Filename(doc.CreatedAt),
			"path":   path,
		})
	}
}

// requestIP extracts the client IP from r.RemoteAddr, falling back to the raw
// value when it has no port.
func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeControlJSON(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
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

// runHealthcheck is the `healthcheck` subcommand used as the stack
// healthcheck.test. It probes the proxy's own plaintext internal listener
// (PROXY_INTERNAL_LISTEN) for a 200 from /_swc/version and returns a process
// exit code (0 = healthy). The external listener is mTLS, so the loopback
// internal listener is the only local path that needs no client cert — the same
// listener rbac-proxy already exposes for its admin control plane. Reading
// cfg.InternalListen (not a hardcoded 127.0.0.1:2375) guarantees the probe
// targets whatever the server actually binds.
func runHealthcheck() int {
	cfg, err := config.Load(os.Getenv("PROXY_CONFIG"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: config: %v\n", err)
		return 1
	}
	if cfg.InternalListen == "" {
		fmt.Fprintln(os.Stderr, "healthcheck: PROXY_INTERNAL_LISTEN not set")
		return 1
	}
	host, port, err := net.SplitHostPort(cfg.InternalListen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: bad internal listen %q: %v\n", cfg.InternalListen, err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if err := healthProbe("http://" + net.JoinHostPort(host, port) + "/_swc/version"); err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	return 0
}

// healthProbe GETs url with a short timeout and returns nil only on HTTP 200.
func healthProbe(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println(version.String())
			return
		case "healthcheck":
			os.Exit(runHealthcheck())
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
	var rbacStore store.RBACStore
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
		rbacStore = sq
	case "memory":
		ms := store.NewMemoryStore()
		ms.SetTokenTTL(cfg.OnboardingTokenTTL)
		userStore = ms
		auditStore = ms
		rbacStore = ms
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
		rbacStore = pg
	default:
		l().Fatalw("unknown store type", "store", cfg.Store)
	}
	l().Infow("onboarding token TTL", "ttl", cfg.OnboardingTokenTTL)

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

	// Seed the built-in roles (idempotent; never clobbers admin edits) and
	// migrate any users that predate RBAC into a role binding derived from
	// their legacy User.Role (admin → admin, else → operator).
	if err := store.SeedDefaultRoles(context.Background(), rbacStore); err != nil {
		l().Fatalw("seed default roles failed", "error", err)
	}
	if err := store.MigrateLegacyRoles(context.Background(), userStore, rbacStore); err != nil {
		l().Fatalw("legacy role migration failed", "error", err)
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

	// RBAC middleware: enforces per-role resource/verb authorization on the
	// proxy data plane. It reuses the guard for stack-label resolution.
	rbacMW := api.NewRBACMiddleware(rbacStore, auditStore, guard)

	userHandler := api.NewUserHandler(userStore, rbacStore, auditStore, cfg.ExternalURL)
	onboardHandler := api.NewOnboardHandler(userStore, ca, cfg.ExternalURL, auditStore)
	meHandler := api.NewMeHandler()
	roleHandler := api.NewRoleHandler(rbacStore, userStore, auditStore)
	bindingHandler := api.NewBindingHandler(rbacStore, userStore, auditStore)

	var proxyAuth func(http.Handler) http.Handler
	var rbacWrap func(http.Handler) http.Handler
	if cfg.TLSClientCA != "" {
		proxyAuth = func(next http.Handler) http.Handler {
			return api.RequireClientCert(userStore, next)
		}
		// RBAC can only be enforced when callers are identified by mTLS.
		rbacWrap = rbacMW.Wrap
	} else {
		proxyAuth = func(next http.Handler) http.Handler { return next }
		rbacWrap = func(next http.Handler) http.Handler { return next }
	}

	var agentManagerProxy http.Handler
	if cfg.AgentManagerURL != "" {
		agentBE, err := parseBackend(cfg.AgentManagerURL)
		if err != nil {
			l().Fatalw("parse agent-manager URL", "error", err)
		}
		warnIfUnqualifiedAgentManagerHost(agentBE.address)

		// Mutual TLS on the rbac-proxy → agent-manager hop. This replaces
		// the confidentiality the encrypted overlay used to provide and
		// additionally authenticates the agent-manager — defence the
		// IPsec overlay never offered. Required (fail-closed) whenever the
		// URL is wss://. ServerName is pinned to internalServerName below:
		// the internal-server cert carries fixed, stack-name-independent
		// SANs (swarmcli-agent / swarmcli-agent-manager), so verification
		// must NOT use the stack-qualified dial host (e.g.
		// "<stack>_agent-manager"), which is not a SAN.
		tlsUpstream := strings.HasPrefix(cfg.AgentManagerURL, "wss://") ||
			strings.HasPrefix(cfg.AgentManagerURL, "https://")
		if tlsUpstream {
			// PROXY_AGENT_MANAGER_TLS_BUNDLE (one PEM: cert+key+CA) supersedes
			// the CA/Cert/Key trio; the trio is the fallback for older bootstraps.
			switch {
			case cfg.AgentManagerTLSBundle != "":
				agentBE.tlsConfig, err = buildBundleTLS(cfg.AgentManagerTLSBundle)
			case cfg.AgentManagerTLSCert != "" && cfg.AgentManagerTLSKey != "" && cfg.AgentManagerTLSCA != "":
				agentBE.tlsConfig, err = buildBackendTLS(
					cfg.AgentManagerTLSCA, cfg.AgentManagerTLSCert, cfg.AgentManagerTLSKey)
			default:
				l().Fatalw("agent-manager TLS misconfigured",
					"error", "wss:// agent-manager URL requires PROXY_AGENT_MANAGER_TLS_BUNDLE (or _TLS_CERT, _KEY and _CA together)")
			}
			if err != nil {
				l().Fatalw("invalid agent-manager TLS config", "error", err)
			}
			agentBE.tlsConfig.MinVersion = tls.VersionTLS13
			agentBE.tlsConfig.ServerName = internalServerName
		}

		agentManagerProxy = newProxy(agentBE)
		l().Infow("agent-manager forwarding enabled",
			"url", cfg.AgentManagerURL, "tls", tlsUpstream)

		// Volume-ownership back-query: the guard resolves a volume's stack via
		// the agent-manager (volumes are node-local; the Docker-socket
		// back-query can't see them). Same mTLS material and SAN pinning as
		// the reverse proxy above.
		bqScheme := "http"
		bqTransport := &http.Transport{}
		if tlsUpstream {
			bqScheme = "https"
			bqTransport.TLSClientConfig = agentBE.tlsConfig
		}
		guard.SetAgentManager(
			&http.Client{Timeout: 5 * time.Second, Transport: bqTransport},
			bqScheme+"://"+agentBE.address,
		)
	}

	dockerProxy := guard.Wrap(newProxy(b))

	// registerRoutes sets up the mux with the given middleware wrappers for
	// proxy routes. wrapProxy resolves identity (RequireClientCert externally,
	// MarkInternalRequest internally). wrapRBAC enforces role-based access
	// (external only; no-op internally and when mTLS is off). wrapExec applies
	// the protected-stack exec/forward guard (no-op on the internal listener).
	registerRoutes := func(mux *http.ServeMux, internal bool, wrapProxy, wrapRBAC, wrapExec, wrapAdmin func(http.Handler) http.Handler) {
		mountControlPlane(mux, internal, userStore, auditStore, backup.DefaultDir(cfg))
		// Management plane (users / roles / bindings). wrapAdmin authorizes the
		// caller: the admin bearer token OR (external listener) an mTLS-
		// authenticated admin, so an admin can manage users from the TUI — which
		// carries a client cert but no bearer token — while the bearer path keeps
		// CLI/bootstrap/internal-listener access. See api.RequireAdminOrToken.
		mux.Handle("/api/v1/users", wrapAdmin(userHandler))
		mux.Handle("POST /api/v1/users/{username}/regenerate-token", wrapAdmin(http.HandlerFunc(userHandler.RegenerateToken)))
		mux.Handle("PATCH /api/v1/users/{username}", wrapAdmin(http.HandlerFunc(userHandler.Update)))
		mux.Handle("DELETE /api/v1/users/{username}", wrapAdmin(http.HandlerFunc(userHandler.Delete)))
		mux.Handle("GET /api/v1/onboard/{token}", onboardHandler)
		mux.Handle("GET /api/v1/roles", wrapAdmin(http.HandlerFunc(roleHandler.List)))
		mux.Handle("POST /api/v1/roles", wrapAdmin(http.HandlerFunc(roleHandler.Create)))
		mux.Handle("GET /api/v1/roles/{name}", wrapAdmin(http.HandlerFunc(roleHandler.Get)))
		mux.Handle("PUT /api/v1/roles/{name}", wrapAdmin(http.HandlerFunc(roleHandler.Update)))
		mux.Handle("DELETE /api/v1/roles/{name}", wrapAdmin(http.HandlerFunc(roleHandler.Delete)))
		mux.Handle("GET /api/v1/bindings", wrapAdmin(http.HandlerFunc(bindingHandler.List)))
		mux.Handle("POST /api/v1/bindings", wrapAdmin(http.HandlerFunc(bindingHandler.Create)))
		mux.Handle("DELETE /api/v1/bindings/{id}", wrapAdmin(http.HandlerFunc(bindingHandler.Delete)))
		// Self-identity: cert-authenticated (wrapProxy = RequireClientCert on
		// the external listener), so the caller's role is resolved from their
		// mTLS CN. On the internal listener wrapProxy is MarkInternalRequest,
		// which sets no user, so this returns 401 there — the internal listener
		// has no per-user identity and is not used for role discovery.
		mux.Handle("GET /api/v1/me", wrapProxy(meHandler))
		if agentManagerProxy != nil {
			mux.Handle("/v1/", wrapProxy(wrapRBAC(wrapExec(agentManagerProxy))))
		}
		mux.Handle("/", wrapProxy(wrapRBAC(wrapExec(dockerProxy))))
	}

	l().Infow("proxy listening", "addr", listenAddr, "backend_network", b.network, "backend_addr", b.address)
	if b.tlsConfig != nil {
		l().Infow("backend TLS enabled")
	}

	// Internal listener (plain TCP, no mTLS) — for admin access from localhost.
	if cfg.InternalListen != "" {
		internalMux := http.NewServeMux()
		noWrap := func(next http.Handler) http.Handler { return next }
		// Internal listener: trusted loopback. Management stays bearer-token
		// protected exactly as before (no mTLS identity here for the admin path).
		internalAdmin := func(next http.Handler) http.Handler { return api.RequireToken(cfg.AdminToken, next) }
		registerRoutes(internalMux, true, api.MarkInternalRequest, noWrap, noWrap, internalAdmin)
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
	// External management auth: resolve identity (proxyAuth = RequireClientCert
	// when mTLS is on) then admit the admin bearer token OR an mTLS-authenticated
	// admin. Without mTLS, proxyAuth is a no-op and only the bearer token admits.
	externalAdmin := func(next http.Handler) http.Handler {
		return proxyAuth(api.RequireAdminOrToken(cfg.AdminToken, rbacStore, auditStore, next))
	}
	registerRoutes(externalMux, false, proxyAuth, rbacWrap, guard.ExecGuard, externalAdmin)

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
