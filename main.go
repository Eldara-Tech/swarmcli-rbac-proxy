package main

import (
	"context"
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

// newProxy builds the reverse-proxy handler for the given Docker socket path.
func newProxy(socketPath string) http.Handler {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	target := &url.URL{Scheme: "http", Host: "docker"}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = "docker"
		},
		Transport: transport,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			handleUpgrade(w, r, socketPath)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// handleUpgrade proxies HTTP upgrade (hijack) requests used by
// docker exec, docker attach, and raw streaming endpoints.
func handleUpgrade(w http.ResponseWriter, r *http.Request, socketPath string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	backConn, err := net.Dial("unix", socketPath)
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
	listenAddr := env("PROXY_LISTEN", ":2376")
	socketPath := env("PROXY_DOCKER_SOCKET", "/var/run/docker.sock")
	tlsCert := os.Getenv("PROXY_TLS_CERT")
	tlsKey := os.Getenv("PROXY_TLS_KEY")

	handler := newProxy(socketPath)

	log.Printf("proxy listening on %s → %s", listenAddr, socketPath)
	if tlsCert != "" && tlsKey != "" {
		log.Printf("TLS enabled (cert=%s key=%s)", tlsCert, tlsKey)
		log.Fatal(http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, handler))
	} else {
		log.Fatal(http.ListenAndServe(listenAddr, handler))
	}
}
