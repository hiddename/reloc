package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
	"github.com/uhiddename/reloc/migrations"
	"golang.org/x/crypto/ssh"
)

// testEnv is an App on the local database plus a raw pool for checks and cleanup.
type testEnv struct {
	app *App
	st  *store.Store
	db  *pgxpool.Pool
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
	// the default is the number of CPUs, which a small server may not allow
	// while other packages run; concurrent tests still race through 3 connections
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
	return testEnv{app: New(st), st: st, db: db}
}

var testHostSeq atomic.Int64

// server creates a host and a WireGuard server on it with the given networks
// (empty string means no network of that family). Everything, clients
// included, is deleted when the test ends.
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
		Name: fmt.Sprintf("app/%s-%d", t.Name(), testHostSeq.Add(1)),
		SSH: vpn.SSH{
			Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 22),
			User:    "root",
			HostKey: hostKey,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
		IPv4:          testNetworkPtr(ipv4),
		IPv6:          testNetworkPtr(ipv6),
		Protocol:      vpn.WireGuardServer{PrivateKey: wg.Genkey()},
	}
	srv, err = e.st.CreateServer(ctx, srv)
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

// testNetworkPtr turns "10.66.66.1/24" into a network with the server at .1.
func testNetworkPtr(s string) *vpn.Network {
	if s == "" {
		return nil
	}
	p := netip.MustParsePrefix(s)
	return &vpn.Network{Prefix: p.Masked(), Addr: p.Addr()}
}

func TestWithAuth(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	withAuth := e.app.WithAuth(ssh.Password("unused"))

	// a missing server stops the apply right after the auth check
	if _, err := withAuth.ApplyServer(ctx, -1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("with auth: err = %v, want store.ErrNotFound", err)
	}
	if _, err := e.app.ApplyServer(ctx, -1); !errors.Is(err, ErrNoAuth) {
		t.Errorf("original App: err = %v, want ErrNoAuth", err)
	}
}
