package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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

func (e testEnv) post(path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func (e testEnv) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, r)
	return w
}

func applyPath(serverID string) string {
	return "/api/v1/servers/" + serverID + "/apply"
}

func TestApplyServerBadID(t *testing.T) {
	h := New(nil, testToken)
	for _, id := range []string{"abc", "0", "-1", "1.5", "99999999999999999999"} {
		t.Run(id, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, applyPath(id), nil)
			r.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantError(t, w, http.StatusBadRequest, "server id must be a positive number")
		})
	}
}

func TestApplyServerRequiresToken(t *testing.T) {
	h := New(nil, testToken)
	r := httptest.NewRequest(http.MethodPost, applyPath("1"), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantError(t, w, http.StatusUnauthorized, "unauthorized")
}

func TestApplyServerNoKey(t *testing.T) {
	h := New(app.New(nil), testToken)
	r := httptest.NewRequest(http.MethodPost, applyPath("1"), nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	wantError(t, w, http.StatusServiceUnavailable, "ssh key is not configured")
}

func TestApplyServerNotFound(t *testing.T) {
	e := newTestEnv(t)
	e.handler = New(app.New(e.st).WithAuth(ssh.Password("unused")), testToken)

	w := e.do(http.MethodPost, applyPath(fmt.Sprint(int64(1<<62))), "")
	wantError(t, w, http.StatusNotFound, "not found")
}
