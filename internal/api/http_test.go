package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInternalErrorHidesDetails(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	// a canceled request makes the database call fail
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, clientsPath(srv.ID), nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)

	wantError(t, w, http.StatusInternalServerError, "internal error")
	for _, s := range []string{"store:", "app:", "context"} {
		if strings.Contains(w.Body.String(), s) {
			t.Errorf("response reveals %q: %s", s, w.Body)
		}
	}
}
