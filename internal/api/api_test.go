package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
	"github.com/uhiddename/reloc/migrations"
	"golang.org/x/crypto/ssh"
)

const testToken = "test-token"

type testEnv struct {
	handler http.Handler
	app     *app.App
	st      *store.Store
	db      *pgxpool.Pool
}

// newTestEnv connects to DATABASE_URL and applies migrations.
// Tests that use it are skipped when DATABASE_URL is not set.
func newTestEnv(t *testing.T) testEnv {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set")
	}
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 3
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	dir, err := fs.Sub(migrations.Postgres, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, dir); err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	a := app.New(st)
	return testEnv{handler: New(a, testToken), app: a, st: st, db: db}
}

var testHostSeq atomic.Int64

// server creates a host and a server with the given networks (empty string
// means no network of that family). Everything is deleted when the test ends.
func (e testEnv) server(t *testing.T, ipv4, ipv6 string) vpn.Server {
	t.Helper()
	ctx := context.Background()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	h, err := e.st.CreateHost(ctx, vpn.Host{
		Name: fmt.Sprintf("api/%s-%d", t.Name(), testHostSeq.Add(1)),
		SSH: vpn.SSH{
			Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 22),
			User:    "root",
			HostKey: hostKey,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := e.st.CreateServer(ctx, vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
		IPv4:          testNetwork(ipv4),
		IPv6:          testNetwork(ipv6),
		Protocol:      vpn.WireGuardServer{PrivateKey: wg.Genkey()},
	})
	// registered before the error check, so the host is removed either way
	t.Cleanup(func() {
		for _, q := range []struct {
			sql string
			id  int64
		}{
			{"delete from vpn_clients where server_id = $1", srv.ID},
			{"delete from vpn_servers where id = $1", srv.ID},
			{"delete from hosts where id = $1", h.ID},
		} {
			if _, err := e.db.Exec(context.Background(), q.sql, q.id); err != nil {
				t.Error(err)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func testNetwork(s string) *vpn.Network {
	if s == "" {
		return nil
	}
	p := netip.MustParsePrefix(s)
	return &vpn.Network{Prefix: p.Masked(), Addr: p.Addr()}
}

func (e testEnv) get(path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func clientsPath(serverID int64) string {
	return fmt.Sprintf("/api/v1/servers/%d/clients", serverID)
}

func wantError(t *testing.T, w *httptest.ResponseRecorder, status int, msg string) {
	t.Helper()
	if w.Code != status {
		t.Errorf("status = %d, want %d; body: %s", w.Code, status, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	if got.Error != msg {
		t.Errorf("error = %q, want %q", got.Error, msg)
	}
}

func TestNewEmptyToken(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New() with an empty token did not panic")
		}
	}()
	New(nil, "")
}

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

func (e testEnv) post(path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
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

func (e testEnv) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
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
