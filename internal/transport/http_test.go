package transport

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostAndOriginAdmission(t *testing.T) {
	calls := 0
	handler, err := NewHandler(Config{AllowedHosts: []string{"budget.example.test", "budget.example.test:8443"}, AllowedOrigins: []string{"https://client.example.test"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, host string
		origins    []string
		want       int
	}{
		{"nonbrowser", "budget.example.test", nil, 204},
		{"allowed browser", "budget.example.test", []string{"https://client.example.test"}, 204},
		{"host case", "BUDGET.EXAMPLE.TEST", nil, 204},
		{"explicit port", "budget.example.test:8443", nil, 204},
		{"wrong host", "attacker.example.test", nil, 403},
		{"host suffix", "budget.example.test.attacker.test", nil, 403},
		{"unlisted port", "budget.example.test:80", nil, 403},
		{"host trailing dot", "budget.example.test.", nil, 403},
		{"wrong origin", "budget.example.test", []string{"https://evil.example.test"}, 403},
		{"origin path", "budget.example.test", []string{"https://client.example.test/path"}, 403},
		{"null origin", "budget.example.test", []string{"null"}, 403},
		{"empty origin", "budget.example.test", []string{""}, 403},
		{"multiple origin", "budget.example.test", []string{"https://client.example.test", "https://evil.example.test"}, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://budget.example.test/mcp", nil)
			req.Host = tc.host
			for _, origin := range tc.origins {
				req.Header.Add("Origin", origin)
			}
			req.Header.Set("X-Forwarded-Host", "budget.example.test")
			req.Header.Set("Forwarded", "host=budget.example.test")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d", rec.Code, tc.want)
			}
			if rec.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unexpected permissive CORS")
			}
		})
	}
	if calls != 4 {
		t.Fatalf("denied requests reached app: %d", calls)
	}
}

func TestBodyBoundAppliesToKnownAndChunkedLengths(t *testing.T) {
	calls := 0
	handler, err := NewHandler(Config{AllowedHosts: []string{"budget.example.test"}, MaxBodyBytes: 16}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if !errors.As(err, &tooLarge) {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(body) > 16 {
				t.Fatal("excess bytes reached handler")
			}
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(204)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body    string
		chunked bool
		want    int
	}{{strings.Repeat("a", 16), false, 204}, {strings.Repeat("a", 17), false, 413}, {strings.Repeat("a", 17), true, 413}} {
		req := httptest.NewRequest(http.MethodPost, "https://budget.example.test/mcp", strings.NewReader(tc.body))
		if tc.chunked {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("got %d want %d", rec.Code, tc.want)
		}
	}
	if calls != 2 {
		t.Fatalf("known oversized body entered handler: %d", calls)
	}
}

func TestRequestDeadlinePropagatesAndExpires(t *testing.T) {
	handler, err := NewHandler(Config{AllowedHosts: []string{"budget.example.test"}, RequestTimeout: 20 * time.Millisecond}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 25*time.Millisecond {
			t.Fatal("request deadline missing")
		}
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://budget.example.test/mcp", nil))
	if rec.Code != 504 || time.Since(start) > time.Second {
		t.Fatal("deadline not enforced")
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cases := []Config{
		{},
		{AllowedHosts: []string{"*"}},
		{AllowedHosts: []string{"https://budget.example.test"}},
		{AllowedHosts: []string{"budget.example.test/path"}},
		{AllowedHosts: []string{"budget.example.test"}, AllowedOrigins: []string{"*"}},
		{AllowedHosts: []string{"budget.example.test"}, AllowedOrigins: []string{"null"}},
		{AllowedHosts: []string{"budget.example.test"}, AllowedOrigins: []string{"http://client.example.test"}},
		{AllowedHosts: []string{"budget.example.test"}, AllowedOrigins: []string{"https://client.example.test/"}},
		{AllowedHosts: []string{"budget.example.test"}, AllowedOrigins: []string{"https://client.example.test?secret=1"}},
		{AllowedHosts: []string{"budget.example.test"}, MaxBodyBytes: 2 << 20},
		{AllowedHosts: []string{"budget.example.test"}, RequestTimeout: time.Hour},
	}
	for _, config := range cases {
		if _, err := NewHandler(config, next); err == nil {
			t.Fatalf("accepted invalid config: %#v", config)
		}
	}
	if _, err := NewHandler(Config{AllowedHosts: []string{"budget.example.test"}}, nil); err == nil {
		t.Fatal("accepted missing handler")
	}
}

func TestServerIsBoundedAndLoopbackOnly(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		server, err := NewServer(address, next)
		if err != nil {
			t.Fatal(err)
		}
		if server.Addr != address || server.Handler == nil || server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes > 16<<10 {
			t.Fatal("unbounded HTTP server")
		}
	}
	for _, address := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "localhost:8080", "127.0.0.1", "127.0.0.1:abc", "127.0.0.1:65536"} {
		if _, err := NewServer(address, next); err == nil {
			t.Fatalf("accepted bind %s", address)
		}
	}
}
