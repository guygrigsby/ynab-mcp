// Package transport applies HTTP admission limits independently of MCP framing.
// Listening or deployment is the composition root's separately approved work.
package transport

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// AllowedHosts contains exact authorities, including a port when present.
	// Forwarded and X-Forwarded-* headers are deliberately never trusted.
	AllowedHosts []string
	// AllowedOrigins is an exact list of browser origins. No Origin header is
	// normal for non-browser OAuth clients. "null" and wildcards are refused.
	AllowedOrigins []string
	MaxBodyBytes   int64
	RequestTimeout time.Duration
}

func NewHandler(config Config, next http.Handler) (http.Handler, error) {
	if next == nil || len(config.AllowedHosts) == 0 {
		return nil, errors.New("handler and explicit host allowlist are required")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = 64 << 10
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > 1<<20 || config.RequestTimeout <= 0 || config.RequestTimeout > time.Minute {
		return nil, errors.New("invalid request limits")
	}
	hosts := make(map[string]bool, len(config.AllowedHosts))
	for _, host := range config.AllowedHosts {
		if !validAuthority(host) {
			return nil, errors.New("invalid allowed host")
		}
		hosts[strings.ToLower(host)] = true
	}
	origins := make(map[string]bool, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || !validAuthority(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
			return nil, errors.New("allowed origins must be exact HTTPS origins")
		}
		origins[origin] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if !hosts[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		originHeaders := r.Header.Values("Origin")
		if len(originHeaders) > 1 || (len(originHeaders) == 1 && !origins[originHeaders[0]]) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		// No permissive CORS headers are generated. An allowed Origin is an
		// admission check, never a substitute for the bearer-token boundary.
		if r.ContentLength > config.MaxBodyBytes {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), config.RequestTimeout)
		defer cancel()
		deadline, _ := ctx.Deadline()
		controller := http.NewResponseController(w)
		// These protect slow/chunked bodies and stalled writes on real servers.
		// Response wrappers must implement Unwrap to retain these controls.
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		request := r.WithContext(ctx)
		if request.Body != nil {
			request.Body = http.MaxBytesReader(w, request.Body, config.MaxBodyBytes)
		}
		next.ServeHTTP(w, request)
	}), nil
}

// NewServer provides bounded server-level limits. It neither opens a socket nor
// accepts forwarding headers. A loopback TLS-proxy deployment must explicitly
// supply its approved bind address; public TLS remains outside this skeleton.
func NewServer(address string, handler http.Handler) (*http.Server, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || handler == nil {
		return nil, errors.New("an explicit loopback address and handler are required")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return nil, errors.New("an explicit numeric port is required")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("the HTTP listener must bind a loopback IP")
	}
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, nil
}

func validAuthority(authority string) bool {
	if authority == "" || strings.ContainsAny(authority, "*/\\?#@ \t\r\n") {
		return false
	}
	u, err := url.Parse("https://" + authority)
	return err == nil && u.Host == authority && u.Hostname() != "" && u.Path == "" && u.User == nil
}
