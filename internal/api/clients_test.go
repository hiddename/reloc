package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

func clientsPath(serverID int64) string {
	return fmt.Sprintf("/api/v1/servers/%d/clients", serverID)
}

func TestListClientsBadID(t *testing.T) {
	h := New(nil, testToken)
	for _, id := range []string{"abc", "0", "-1", "1.5", "99999999999999999999"} {
		t.Run(id, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/servers/"+id+"/clients", nil)
			r.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantError(t, w, http.StatusBadRequest, "server id must be a positive number")
		})
	}
}

func TestListClientsNotFound(t *testing.T) {
	e := newTestEnv(t)
	wantError(t, e.get(clientsPath(1<<62)), http.StatusNotFound, "not found")
}

func TestListClientsEmpty(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	w := e.get(clientsPath(srv.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("body = %q, want []", got)
	}
}

func TestListClients(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv := e.server(t, "10.66.66.1/24", "fd42::1/64")
	v4 := e.server(t, "10.77.77.1/24", "")

	dual, err := e.app.CreateClient(ctx, srv.ID, "dual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.CreateClient(ctx, v4.ID, "other-server", nil); err != nil {
		t.Fatal(err)
	}

	w := e.get(clientsPath(srv.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d clients, want 1: %s", len(got), w.Body)
	}
	c := got[0]
	for field, want := range map[string]any{
		"id":        float64(dual.ID),
		"server_id": float64(srv.ID),
		"name":      "dual",
		"ipv4":      "10.66.66.2",
		"ipv6":      "fd42::2",
		"enabled":   true,
	} {
		if c[field] != want {
			t.Errorf("%s = %v, want %v", field, c[field], want)
		}
	}
	if nets, _ := c["tunnel_networks"].([]any); len(nets) != len(dual.TunnelNetworks) {
		t.Errorf("tunnel_networks = %v, want %v", c["tunnel_networks"], dual.TunnelNetworks)
	}
	if s, _ := c["created_at"].(string); s == "" {
		t.Error("created_at is missing")
	}

	t.Run("no address of a missing family", func(t *testing.T) {
		w := e.get(clientsPath(v4.ID))
		var got []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d clients, want 1: %s", len(got), w.Body)
		}
		if _, ok := got[0]["ipv6"]; ok {
			t.Errorf("ipv6 is present: %s", w.Body)
		}
	})
}

// The fields are compared with a list, so a new field in the response
// has to be added here on purpose.
func TestListClientsFields(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "fd42::1/64")
	if _, err := e.app.CreateClient(context.Background(), srv.ID, "c", nil); err != nil {
		t.Fatal(err)
	}

	w := e.get(clientsPath(srv.ID))
	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d clients, want 1", len(got))
	}
	allowed := map[string]bool{
		"id": true, "server_id": true, "name": true, "ipv4": true, "ipv6": true,
		"tunnel_networks": true, "enabled": true, "created_at": true,
	}
	for field := range got[0] {
		if !allowed[field] {
			t.Errorf("unexpected field %q in the response", field)
		}
	}
}

func TestListClientsNoSecrets(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c, err := e.app.CreateClient(context.Background(), srv.ID, "c", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.WireGuard()
	if err != nil {
		t.Fatal(err)
	}

	body := e.get(clientsPath(srv.ID)).Body.String()
	for name, secret := range map[string]string{
		"private key":   p.PrivateKey.Base64(),
		"preshared key": p.PresharedKey.Base64(),
	} {
		if strings.Contains(body, secret) {
			t.Errorf("response contains the %s", name)
		}
	}
	// encoded differently, a key would still show up under a field name
	for _, s := range []string{"key", "Key", "Protocol", "protocol"} {
		if strings.Contains(body, s) {
			t.Errorf("response contains %q", s)
		}
	}
}

func (e testEnv) clientNames(t *testing.T, serverID int64) []string {
	t.Helper()
	clients, err := e.st.ListClients(context.Background(), serverID)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(clients))
	for _, c := range clients {
		names = append(names, c.Name)
	}
	return names
}

func clientPath(clientID int64) string {
	return fmt.Sprintf("/api/v1/clients/%d", clientID)
}

func (e testEnv) client(t *testing.T, serverID int64, name string) vpn.Client {
	t.Helper()
	c, err := e.app.CreateClient(context.Background(), serverID, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e testEnv) storedEnabled(t *testing.T, clientID int64) bool {
	t.Helper()
	c, err := e.st.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	return c.Enabled
}

func TestClientRoutesBadID(t *testing.T) {
	h := New(nil, testToken)
	routes := []struct{ method, suffix string }{
		{http.MethodPatch, ""},
		{http.MethodDelete, ""},
		{http.MethodGet, "/conf"},
	}
	for _, route := range routes {
		for _, id := range []string{"abc", "0", "-1", "1.5", "99999999999999999999"} {
			t.Run(route.method+route.suffix+"/"+id, func(t *testing.T) {
				path := "/api/v1/clients/" + id + route.suffix
				r := httptest.NewRequest(route.method, path, strings.NewReader(`{}`))
				r.Header.Set("Authorization", "Bearer "+testToken)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				wantError(t, w, http.StatusBadRequest, "client id must be a positive number")
			})
		}
	}
}

func TestClientRoutesNotFound(t *testing.T) {
	e := newTestEnv(t)
	const missing = 1 << 62
	tests := []struct {
		name, method, path, body string
	}{
		{"PATCH", http.MethodPatch, clientPath(missing), `{"enabled": false}`},
		{"PATCH without fields", http.MethodPatch, clientPath(missing), `{}`},
		{"DELETE", http.MethodDelete, clientPath(missing), ""},
		{"GET conf", http.MethodGet, clientPath(missing) + "/conf", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantError(t, e.do(tt.method, tt.path, tt.body), http.StatusNotFound, "not found")
		})
	}
}

func TestClientRoutesRequireToken(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "phone")

	tests := []struct {
		name, method, path, body string
	}{
		{"PATCH", http.MethodPatch, clientPath(c.ID), `{"enabled": false}`},
		{"DELETE", http.MethodDelete, clientPath(c.ID), ""},
		{"GET conf", http.MethodGet, clientPath(c.ID) + "/conf", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			e.handler.ServeHTTP(w, r)
			wantError(t, w, http.StatusUnauthorized, "unauthorized")
		})
	}
	if !e.storedEnabled(t, c.ID) {
		t.Error("client got disabled without a token")
	}
	if got := e.clientNames(t, srv.ID); !slices.Equal(got, []string{"phone"}) {
		t.Errorf("clients = %q, want the client kept", got)
	}
}

func TestUpdateClientEnabled(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "phone")
	other := e.client(t, srv.ID, "laptop")

	for _, want := range []bool{false, false, true, true} { // repeating is not an error
		w := e.do(http.MethodPatch, clientPath(c.ID), fmt.Sprintf(`{"enabled": %v}`, want))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body)
		}
		var got clientResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.ID != c.ID || got.ServerID != srv.ID || got.Name != "phone" || got.Enabled != want {
			t.Errorf("response = %+v, want client %d with enabled = %v", got, c.ID, want)
		}
		if e.storedEnabled(t, c.ID) != want {
			t.Errorf("stored enabled != %v", want)
		}
		if !e.storedEnabled(t, other.ID) {
			t.Error("another client got disabled")
		}
	}
}

func TestUpdateClientNoFields(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "phone")
	if err := e.st.SetClientEnabled(context.Background(), c.ID, false); err != nil {
		t.Fatal(err)
	}

	w := e.do(http.MethodPatch, clientPath(c.ID), `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	var got clientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != c.ID || got.Enabled {
		t.Errorf("response = %+v, want the client as it is", got)
	}
	if e.storedEnabled(t, c.ID) {
		t.Error("an empty update changed enabled")
	}
}

func TestUpdateClientBadRequest(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "phone")

	for name, body := range map[string]string{
		"empty body":    "",
		"broken JSON":   `{"enabled":`,
		"unknown field": `{"enabled": false, "nmae": "x"}`,
		"wrong type":    `{"enabled": "false"}`,
		"not an object": `[false]`,
	} {
		t.Run(name, func(t *testing.T) {
			w := e.do(http.MethodPatch, clientPath(c.ID), body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body)
			}
			if !e.storedEnabled(t, c.ID) {
				t.Fatal("a rejected request disabled the client")
			}
		})
	}
}

func TestUpdateClientNoSecrets(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "phone")
	p, err := c.WireGuard()
	if err != nil {
		t.Fatal(err)
	}

	body := e.do(http.MethodPatch, clientPath(c.ID), `{"enabled": false}`).Body.String()
	for name, secret := range map[string]string{
		"private key":   p.PrivateKey.Base64(),
		"preshared key": p.PresharedKey.Base64(),
	} {
		if strings.Contains(body, secret) {
			t.Errorf("response contains the %s", name)
		}
	}
}

func TestDeleteClient(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	c := e.client(t, srv.ID, "gone")
	e.client(t, srv.ID, "kept")

	w := e.do(http.MethodDelete, clientPath(c.ID), "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body: %s", w.Code, w.Body)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", w.Body)
	}
	if got := e.clientNames(t, srv.ID); !slices.Equal(got, []string{"kept"}) {
		t.Errorf("clients = %q, want only the other one", got)
	}

	// the id is not reused, so a repeated request cannot hit another client
	wantError(t, e.do(http.MethodDelete, clientPath(c.ID), ""), http.StatusNotFound, "not found")
}

func TestClientConf(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	e.client(t, srv.ID, "first")
	c := e.client(t, srv.ID, "second")
	p, err := c.WireGuard()
	if err != nil {
		t.Fatal(err)
	}

	w := e.get(clientPath(c.ID) + "/conf")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Content-Type"), "text/plain; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	conf, err := e.app.ClientConf(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := wg.Render(&want, conf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Body.Bytes(), want.Bytes()) {
		t.Error("body is not the rendered config of the client")
	}
	// the config of this client, not just any valid one
	if !strings.Contains(w.Body.String(), p.PrivateKey.Base64()) {
		t.Error("body does not hold the private key of the client")
	}
	if !strings.Contains(w.Body.String(), "10.66.66.3") {
		t.Error("body does not hold the address of the client")
	}
}

func TestCreateClient(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	w := e.post(clientsPath(srv.ID), `{"name": "phone"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	var got clientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID == 0 || got.Name != "phone" || !got.Enabled {
		t.Errorf("response = %+v", got)
	}
	if got.IPv4 == nil || *got.IPv4 != netip.MustParseAddr("10.66.66.2") {
		t.Errorf("ipv4 = %v, want 10.66.66.2", got.IPv4)
	}
	if !slices.Equal(got.TunnelNetworks, wg.DefaultAllowedIPs()) {
		t.Errorf("tunnel_networks = %v, want the full tunnel", got.TunnelNetworks)
	}

	stored, err := e.st.ListClients(context.Background(), srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].ID != got.ID {
		t.Fatalf("stored = %+v, want the created client", stored)
	}
	p, err := stored[0].WireGuard()
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{
		"private key":   p.PrivateKey.Base64(),
		"preshared key": p.PresharedKey.Base64(),
	} {
		if strings.Contains(w.Body.String(), secret) {
			t.Errorf("response contains the %s", name)
		}
	}
}

func TestCreateClientTunnelNetworks(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	w := e.post(clientsPath(srv.ID), `{"name": "laptop", "tunnel_networks": ["10.66.66.0/24"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body: %s", w.Code, w.Body)
	}
	var got clientResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.66.66.0/24")}
	if !slices.Equal(got.TunnelNetworks, want) {
		t.Errorf("tunnel_networks = %v, want %v", got.TunnelNetworks, want)
	}
}

func TestCreateClientBadRequest(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	tests := []struct {
		name string
		body string
		want string // part of the error
	}{
		{"empty body", "", "invalid JSON"},
		{"not JSON", "name=phone", "invalid JSON"},
		{"cut off", `{"name": "phone"`, "invalid JSON"},
		{"unknown field", `{"name": "phone", "nmae": "x"}`, "invalid JSON"},
		{"wrong type", `{"name": 1}`, "invalid JSON"},
		{"networks as a string", `{"name": "phone", "tunnel_networks": "10.0.0.0/8"}`, "invalid JSON"},
		{"bad network", `{"name": "phone", "tunnel_networks": ["nope"]}`, "invalid JSON"},
		{"too large", `{"name": "` + strings.Repeat("a", maxRequestBody) + `"}`, "invalid JSON"},
		{"no name", `{}`, "client name"},
		{"empty name", `{"name": ""}`, "client name"},
		{"bad name", `{"name": "with space"}`, "client name"},
		{"long name", `{"name": "` + strings.Repeat("a", 16) + `"}`, "client name"},
		{"host bits", `{"name": "phone", "tunnel_networks": ["10.66.66.5/24"]}`, "host bits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := e.post(clientsPath(srv.ID), tt.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %.200s", w.Code, w.Body)
			}
			var got errorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("body is not one JSON value: %.200q: %v", w.Body, err)
			}
			if !strings.Contains(got.Error, tt.want) {
				t.Errorf("error = %.200q, want it to contain %q", got.Error, tt.want)
			}
			if names := e.clientNames(t, srv.ID); len(names) != 0 {
				t.Errorf("clients were created: %q", names)
			}
		})
	}
}

func TestCreateClientBadID(t *testing.T) {
	h := New(nil, testToken)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/servers/abc/clients", strings.NewReader(`{"name": "c"}`))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantError(t, w, http.StatusBadRequest, "server id must be a positive number")
}

func TestCreateClientConflicts(t *testing.T) {
	e := newTestEnv(t)

	t.Run("unknown server", func(t *testing.T) {
		wantError(t, e.post(clientsPath(1<<62), `{"name": "c"}`), http.StatusNotFound, "not found")
	})
	t.Run("name taken", func(t *testing.T) {
		srv := e.server(t, "10.66.66.1/24", "")
		if w := e.post(clientsPath(srv.ID), `{"name": "c"}`); w.Code != http.StatusCreated {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body)
		}
		wantError(t, e.post(clientsPath(srv.ID), `{"name": "c"}`), http.StatusConflict, "client name is already taken")
	})
	t.Run("network full", func(t *testing.T) {
		srv := e.server(t, "10.66.66.1/30", "")
		if w := e.post(clientsPath(srv.ID), `{"name": "a"}`); w.Code != http.StatusCreated {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body)
		}
		wantError(t, e.post(clientsPath(srv.ID), `{"name": "b"}`), http.StatusConflict, "network is full")
	})
}
