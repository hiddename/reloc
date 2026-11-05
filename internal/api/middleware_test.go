package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestToken(t *testing.T) {
	// a nil app: a request that gets past the check panics in the handler
	h := New(nil, testToken)

	tests := []struct {
		name   string
		header string
	}{
		{"no header", ""},
		{"wrong token", "Bearer wrong"},
		{"prefix of the token", "Bearer test-"},
		{"token and more", "Bearer test-token2"},
		{"no scheme", testToken},
		{"another scheme", "Basic " + testToken},
		{"only the scheme", "Bearer "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, clientsPath(1), nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantError(t, w, http.StatusUnauthorized, "unauthorized")
			if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
		})
	}
}

func TestUnknownRouteRequiresToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/no-such-route", nil)
	w := httptest.NewRecorder()
	New(nil, testToken).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogRequests(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	h := New(nil, testToken)
	r := httptest.NewRequest(http.MethodGet, clientsPath(1)+"?secret=query", nil)
	r.Header.Set("Authorization", "Bearer "+testToken+"-wrong")
	h.ServeHTTP(httptest.NewRecorder(), r)

	log := buf.String()
	for _, s := range []string{"method=GET", "path=" + clientsPath(1), "status=401"} {
		if !strings.Contains(log, s) {
			t.Errorf("log lacks %q: %s", s, log)
		}
	}
	for _, s := range []string{testToken, "secret=query"} {
		if strings.Contains(log, s) {
			t.Errorf("log contains %q: %s", s, log)
		}
	}
}

func TestLogRequestsStatus(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			"Write without WriteHeader is 200",
			func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) },
			"status=200",
		},
		{
			"explicit status",
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) },
			"status=418",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			defer slog.SetDefault(prev)

			logRequests(tt.handler).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("log lacks %q: %s", tt.want, buf.String())
			}
		})
	}
}
