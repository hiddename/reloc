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
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func (e testEnv) createClient(t *testing.T, serverID int64, name string) vpn.Client {
	t.Helper()
	c, err := e.app.CreateClient(context.Background(), serverID, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateClient(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "fd42::1/64")

	before := time.Now()
	c := e.createClient(t, srv.ID, "phone")

	if c.ID == 0 || c.CreatedAt.Before(before.Add(-time.Minute)) {
		t.Errorf("ID or CreatedAt not set: %+v", c)
	}
	if c.ServerID != srv.ID || c.Name != "phone" || !c.Enabled {
		t.Errorf("ServerID/Name/Enabled = %d/%q/%v", c.ServerID, c.Name, c.Enabled)
	}
	if want := netip.MustParseAddr("10.66.66.2"); c.IPv4 != want {
		t.Errorf("IPv4 = %v, want %v", c.IPv4, want)
	}
	if want := netip.MustParseAddr("fd42::2"); c.IPv6 != want {
		t.Errorf("IPv6 = %v, want %v", c.IPv6, want)
	}
	if !slices.Equal(c.TunnelNetworks, wg.DefaultAllowedIPs()) {
		t.Errorf("TunnelNetworks = %v, want full tunnel", c.TunnelNetworks)
	}
	p, err := c.WireGuard()
	if err != nil {
		t.Fatal(err)
	}
	if p.PrivateKey == (wg.PrivateKey{}) || p.PresharedKey == (wg.PresharedKey{}) {
		t.Error("keys are not generated")
	}
	if p.PersistentKeepalive != wg.DefaultPersistentKeepalive {
		t.Errorf("PersistentKeepalive = %d, want %d", p.PersistentKeepalive, wg.DefaultPersistentKeepalive)
	}

	// what CreateClient returned is what is stored
	got, err := e.st.ListClients(context.Background(), srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("ListClients() returned %d clients, want 1", len(got))
	}
	if !got[0].CreatedAt.Equal(c.CreatedAt) {
		t.Errorf("stored CreatedAt = %v, want %v", got[0].CreatedAt, c.CreatedAt)
	}
	got[0].CreatedAt, c.CreatedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(got[0], c) {
		t.Errorf("stored client mismatch\ngot:  %+v\nwant: %+v", got[0], c)
	}
}

func TestCreateClientKeysUnique(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	a, _ := e.createClient(t, srv.ID, "a").WireGuard()
	b, _ := e.createClient(t, srv.ID, "b").WireGuard()
	if a.PrivateKey == b.PrivateKey || a.PresharedKey == b.PresharedKey {
		t.Error("two clients got the same keys")
	}
}

func TestCreateClientSplitTunnel(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	tunnel := []netip.Prefix{netip.MustParsePrefix("10.66.66.0/24")}

	c, err := e.app.CreateClient(context.Background(), srv.ID, "laptop", tunnel)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.TunnelNetworks, tunnel) {
		t.Errorf("TunnelNetworks = %v, want %v", c.TunnelNetworks, tunnel)
	}
}

func TestCreateClientV4Only(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	c := e.createClient(t, srv.ID, "phone")
	if want := netip.MustParseAddr("10.66.66.2"); c.IPv4 != want {
		t.Errorf("IPv4 = %v, want %v", c.IPv4, want)
	}
	if c.IPv6.IsValid() {
		t.Errorf("IPv6 = %v, want none", c.IPv6)
	}
}

func TestCreateClientSequence(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "fd42::1/64")
	ctx := context.Background()

	for i, name := range []string{"a", "b", "c"} {
		c := e.createClient(t, srv.ID, name)
		if want := netip.MustParseAddr(fmt.Sprintf("10.66.66.%d", i+2)); c.IPv4 != want {
			t.Errorf("%s: IPv4 = %v, want %v", name, c.IPv4, want)
		}
		if want := netip.MustParseAddr(fmt.Sprintf("fd42::%d", i+2)); c.IPv6 != want {
			t.Errorf("%s: IPv6 = %v, want %v", name, c.IPv6, want)
		}
	}

	// a disabled client keeps its address
	if _, err := e.db.Exec(ctx,
		"update vpn_clients set enabled = false where server_id = $1 and name = 'a'", srv.ID,
	); err != nil {
		t.Fatal(err)
	}
	// a deleted client frees its address
	if _, err := e.db.Exec(ctx,
		"delete from vpn_clients where server_id = $1 and name = 'b'", srv.ID,
	); err != nil {
		t.Fatal(err)
	}

	c := e.createClient(t, srv.ID, "d")
	if want := netip.MustParseAddr("10.66.66.3"); c.IPv4 != want {
		t.Errorf("after delete: IPv4 = %v, want %v", c.IPv4, want)
	}
	if want := netip.MustParseAddr("fd42::3"); c.IPv6 != want {
		t.Errorf("after delete: IPv6 = %v, want %v", c.IPv6, want)
	}
}

func TestCreateClientNetworkFull(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/30", "")

	e.createClient(t, srv.ID, "only")
	c, err := e.app.CreateClient(context.Background(), srv.ID, "extra", nil)
	if !errors.Is(err, ErrNetworkFull) {
		t.Fatalf("CreateClient() = %+v, %v; want ErrNetworkFull", c, err)
	}
	if c.ID != 0 {
		t.Errorf("CreateClient() on error = %+v, want zero", c)
	}
}

func TestCreateClientErrors(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	e.createClient(t, srv.ID, "taken")
	ctx := context.Background()

	t.Run("unknown server", func(t *testing.T) {
		_, err := e.app.CreateClient(ctx, -1, "c", nil)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("err = %v, want store.ErrNotFound", err)
		}
	})
	t.Run("duplicate name", func(t *testing.T) {
		c, err := e.app.CreateClient(ctx, srv.ID, "taken", nil)
		if !errors.Is(err, store.ErrClientNameTaken) {
			t.Fatalf("CreateClient() = %+v, %v; want store.ErrClientNameTaken", c, err)
		}
		if c.ID != 0 {
			t.Errorf("CreateClient() on error = %+v, want zero", c)
		}
	})
}

// createConcurrently calls CreateClient at once from one goroutine per name.
func (e testEnv) createConcurrently(srvID int64, names []string) ([]vpn.Client, []error) {
	var (
		clients = make([]vpn.Client, len(names))
		errs    = make([]error, len(names))
		start   = make(chan struct{})
		wg      sync.WaitGroup
	)
	for i, name := range names {
		wg.Go(func() {
			<-start
			clients[i], errs[i] = e.app.CreateClient(context.Background(), srvID, name, nil)
		})
	}
	close(start)
	wg.Wait()
	return clients, errs
}

func TestCreateClientConcurrent(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "fd42::1/64")
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	clients, errs := e.createConcurrently(srv.ID, names)

	v4 := map[netip.Addr]string{}
	v6 := map[netip.Addr]string{}
	for i, c := range clients {
		if errs[i] != nil {
			t.Errorf("%s: %v", names[i], errs[i])
			continue
		}
		if other, ok := v4[c.IPv4]; ok {
			t.Errorf("%s and %s share %v", names[i], other, c.IPv4)
		}
		if other, ok := v6[c.IPv6]; ok {
			t.Errorf("%s and %s share %v", names[i], other, c.IPv6)
		}
		v4[c.IPv4], v6[c.IPv6] = names[i], names[i]
	}
}

func TestCreateClientConcurrentSameName(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")

	_, errs := e.createConcurrently(srv.ID, slices.Repeat([]string{"same"}, 8))

	created := 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case !errors.Is(err, store.ErrClientNameTaken):
			t.Errorf("err = %v, want store.ErrClientNameTaken", err)
		}
	}
	if created != 1 {
		t.Errorf("created %d clients, want 1", created)
	}
}

func TestCreateClientConcurrentNetworkFull(t *testing.T) {
	e := newTestEnv(t)
	// .2 to .6 are free: .0 is the network, .1 the server, .7 the broadcast
	srv := e.server(t, "10.66.66.1/29", "")
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}

	_, errs := e.createConcurrently(srv.ID, names)

	created := 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case !errors.Is(err, ErrNetworkFull):
			t.Errorf("err = %v, want ErrNetworkFull", err)
		}
	}
	if created != 5 {
		t.Errorf("created %d clients, want 5", created)
	}
}

func TestCreateClientInvalid(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	ctx := context.Background()

	tests := []struct {
		name   string
		client string
		tunnel []netip.Prefix
	}{
		{"bad name", "with space", nil},
		{"empty name", "", nil},
		{"host bits in a tunnel network", "c", []netip.Prefix{netip.MustParsePrefix("10.66.66.5/24")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := e.app.CreateClient(ctx, srv.ID, tt.client, tt.tunnel)
			var invalid *vpn.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("CreateClient() = %+v, %v; want *vpn.ValidationError", c, err)
			}
		})
	}
	// validation goes first: an unknown server is not even looked up
	_, err := e.app.CreateClient(ctx, -1, "with space", nil)
	var invalid *vpn.ValidationError
	if !errors.As(err, &invalid) {
		t.Errorf("unknown server and bad name: err = %v, want *vpn.ValidationError", err)
	}

	clients, err := e.st.ListClients(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 0 {
		t.Errorf("created %d clients", len(clients))
	}
}

func TestServerConf(t *testing.T) {
	e := newTestEnv(t)
	srv := e.server(t, "10.66.66.1/24", "")
	ctx := context.Background()

	on := e.createClient(t, srv.ID, "on")
	off := e.createClient(t, srv.ID, "off")
	if err := e.app.SetClientEnabled(ctx, off.ID, false); err != nil {
		t.Fatal(err)
	}

	conf, err := e.app.ServerConf(ctx, srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Peers) != 1 {
		t.Fatalf("peers = %d, want only the enabled client", len(conf.Peers))
	}
	want := netip.PrefixFrom(on.IPv4, 32)
	if !slices.Contains(conf.Peers[0].AllowedIPs, want) {
		t.Errorf("AllowedIPs = %v, want %v", conf.Peers[0].AllowedIPs, want)
	}
}

func TestServerConfNotFound(t *testing.T) {
	e := newTestEnv(t)
	_, err := e.app.ServerConf(context.Background(), -1)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want store.ErrNotFound", err)
	}
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
