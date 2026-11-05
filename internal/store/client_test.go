package store

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

// testServer creates a host and a WireGuard server on it with
// 10.66.66.0/24 (server .1) and, if dualStack, fd42::/64 (server ::1).
func testServer(t *testing.T, s *Store, dualStack bool) vpn.Server {
	t.Helper()
	h := testHost(t, s)
	srv := vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.66.66.0/24"),
			Addr:   netip.MustParseAddr("10.66.66.1"),
		},
		Protocol: vpn.WireGuardServer{PrivateKey: wg.Genkey()},
	}
	if dualStack {
		srv.IPv6 = &vpn.Network{
			Prefix: netip.MustParsePrefix("fd42::/64"),
			Addr:   netip.MustParseAddr("fd42::1"),
		}
	}
	return createTestServer(t, s, srv)
}

// createTestClient creates a client and deletes it when the test ends.
func createTestClient(t *testing.T, s *Store, c vpn.Client) vpn.Client {
	t.Helper()
	got, err := s.CreateClient(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.db.Exec(context.Background(), "delete from vpn_clients where id = $1", got.ID); err != nil {
			t.Error(err)
		}
	})
	return got
}

func newTestClient(serverID int64, name string, addrs ...string) vpn.Client {
	c := vpn.Client{
		ServerID:       serverID,
		Name:           name,
		TunnelNetworks: wg.DefaultAllowedIPs(),
		Enabled:        true,
		Protocol: vpn.WireGuardClient{
			PrivateKey:          wg.Genkey(),
			PresharedKey:        wg.Genpsk(),
			PersistentKeepalive: wg.DefaultPersistentKeepalive,
		},
	}
	for _, a := range addrs {
		addr := netip.MustParseAddr(a)
		if addr.Is4() {
			c.IPv4 = addr
		} else {
			c.IPv6 = addr
		}
	}
	return c
}

func TestCreateClient(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, true)
	in := newTestClient(srv.ID, "phone", "10.66.66.2", "fd42::2")
	wgc := in.Protocol.(vpn.WireGuardClient)

	c := createTestClient(t, s, in)
	if c.ID == 0 || c.CreatedAt.IsZero() {
		t.Fatalf("ID or CreatedAt not set: %+v", c)
	}

	var (
		protocol, name string
		ipv4, ipv6     *netip.Addr
		tunnel         []netip.Prefix
		enabled        bool
		priv, pub, psk []byte
		keepalive      *int32
	)
	err := s.db.QueryRow(context.Background(), `
select v.protocol, v.name, v.ipv4_address, v.ipv6_address, v.tunnel_networks, v.enabled,
       w.private_key, w.public_key, w.preshared_key, w.persistent_keepalive
from vpn_clients v join wg_clients w on w.client_id = v.id
where v.id = $1`, c.ID).Scan(
		&protocol, &name, &ipv4, &ipv6, &tunnel, &enabled,
		&priv, &pub, &psk, &keepalive,
	)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "wireguard" || name != "phone" || !enabled {
		t.Errorf("protocol/name/enabled = %s/%s/%v", protocol, name, enabled)
	}
	if ipv4 == nil || *ipv4 != in.IPv4 || ipv6 == nil || *ipv6 != in.IPv6 {
		t.Errorf("addresses = %v/%v, want %v/%v", deref(ipv4), deref(ipv6), in.IPv4, in.IPv6)
	}
	if !slices.Equal(tunnel, in.TunnelNetworks) {
		t.Errorf("tunnel_networks = %v, want %v", tunnel, in.TunnelNetworks)
	}
	if !slices.Equal(priv, wgc.PrivateKey.Bytes()) ||
		!slices.Equal(pub, wgc.PrivateKey.PublicKey().Bytes()) ||
		!slices.Equal(psk, wgc.PresharedKey.Bytes()) {
		t.Error("keys do not match")
	}
	if keepalive == nil || *keepalive != int32(wg.DefaultPersistentKeepalive) {
		t.Errorf("persistent_keepalive = %v, want %d", deref(keepalive), wg.DefaultPersistentKeepalive)
	}
}

func TestCreateClientKeepaliveOff(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, false)
	in := newTestClient(srv.ID, "laptop", "10.66.66.2")
	p := in.Protocol.(vpn.WireGuardClient)
	p.PersistentKeepalive = 0
	in.Protocol = p

	c := createTestClient(t, s, in)
	var keepalive *int32
	if err := s.db.QueryRow(context.Background(),
		"select persistent_keepalive from wg_clients where client_id = $1", c.ID,
	).Scan(&keepalive); err != nil {
		t.Fatal(err)
	}
	if keepalive != nil {
		t.Errorf("persistent_keepalive = %d, want NULL", *keepalive)
	}
}

func TestCreateClientRejected(t *testing.T) {
	s := testStore(t)
	dual := testServer(t, s, true)
	v4only := testServer(t, s, false)
	createTestClient(t, s, newTestClient(dual.ID, "taken", "10.66.66.10", "fd42::10"))

	noTunnel := newTestClient(dual.ID, "no-tunnel", "10.66.66.20", "fd42::20")
	noTunnel.TunnelNetworks = nil
	noProtocol := newTestClient(dual.ID, "no-protocol", "10.66.66.21", "fd42::21")
	noProtocol.Protocol = nil

	tests := []struct {
		name   string
		client vpn.Client
	}{
		{"v4 only on dual-stack server", newTestClient(dual.ID, "c", "10.66.66.2")},
		{"v6 on v4-only server", newTestClient(v4only.ID, "c", "10.66.66.2", "fd42::2")},
		{"outside server network", newTestClient(dual.ID, "c", "10.0.0.2", "fd42::2")},
		{"server address", newTestClient(dual.ID, "c", "10.66.66.1", "fd42::2")},
		{"network address", newTestClient(dual.ID, "c", "10.66.66.0", "fd42::2")},
		{"broadcast address", newTestClient(dual.ID, "c", "10.66.66.255", "fd42::2")},
		{"server v6 address", newTestClient(dual.ID, "c", "10.66.66.2", "fd42::1")},
		{"duplicate name", newTestClient(dual.ID, "taken", "10.66.66.2", "fd42::2")},
		{"duplicate address", newTestClient(dual.ID, "c", "10.66.66.10", "fd42::2")},
		{"no tunnel networks", noTunnel},
		{"no protocol", noProtocol},
		{"unknown server", newTestClient(-1, "c", "10.66.66.2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := s.CreateClient(context.Background(), tt.client)
			if err == nil {
				t.Cleanup(func() { s.db.Exec(context.Background(), "delete from vpn_clients where id = $1", c.ID) })
				t.Fatalf("CreateClient() succeeded: %+v", c)
			}
			if c.ID != 0 {
				t.Errorf("CreateClient() on error = %+v, want zero", c)
			}
		})
	}
}

func TestCreateClientRollback(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, false)
	ctx := context.Background()

	first := createTestClient(t, s, newTestClient(srv.ID, "first", "10.66.66.2"))

	// same keys: the public key is unique per server, so the wg_clients insert
	// fails after the vpn_clients insert
	second := newTestClient(srv.ID, "second", "10.66.66.3")
	second.Protocol = first.Protocol
	if _, err := s.CreateClient(ctx, second); err == nil {
		t.Fatal("CreateClient() with duplicate public key succeeded")
	}

	var n int
	if err := s.db.QueryRow(ctx,
		"select count(*) from vpn_clients where server_id = $1 and name = 'second'", srv.ID,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("vpn_clients row left after failed insert: count = %d", n)
	}
}

func TestListClients(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, true)

	disabled := newTestClient(srv.ID, "disabled", "10.66.66.4", "fd42::4")
	disabled.Enabled = false
	noKeepalive := newTestClient(srv.ID, "no-keepalive", "10.66.66.3", "fd42::3")
	p := noKeepalive.Protocol.(vpn.WireGuardClient)
	p.PersistentKeepalive = 0
	noKeepalive.Protocol = p
	split := newTestClient(srv.ID, "split", "10.66.66.5", "fd42::5")
	split.TunnelNetworks = []netip.Prefix{netip.MustParsePrefix("10.66.66.0/24")}

	// created in this order, so ids are ascending
	var want []vpn.Client
	for _, c := range []vpn.Client{
		newTestClient(srv.ID, "phone", "10.66.66.2", "fd42::2"),
		noKeepalive,
		disabled,
		split,
	} {
		want = append(want, createTestClient(t, s, c))
	}

	// a client of another server must not show up
	other := testServer(t, s, false)
	createTestClient(t, s, newTestClient(other.ID, "other", "10.66.66.2"))

	got, err := s.ListClients(context.Background(), srv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("ListClients() returned %d clients, want %d", len(got), len(want))
	}
	for i := range want {
		if !got[i].CreatedAt.Equal(want[i].CreatedAt) {
			t.Errorf("client %d CreatedAt = %v, want %v", i, got[i].CreatedAt, want[i].CreatedAt)
		}
		got[i].CreatedAt, want[i].CreatedAt = time.Time{}, time.Time{}
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("client %d mismatch\ngot:  %+v\nwant: %+v", i, got[i], want[i])
		}
	}
}

func TestListClientsEmpty(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, false)

	for _, id := range []int64{srv.ID, -1} {
		got, err := s.ListClients(context.Background(), id)
		if err != nil {
			t.Fatalf("ListClients(%d) err = %v", id, err)
		}
		if got == nil || len(got) != 0 {
			t.Errorf("ListClients(%d) = %#v, want empty non-nil slice", id, got)
		}
	}
}

func clientNames(t *testing.T, s *Store, serverID int64) []string {
	t.Helper()
	clients, err := s.ListClients(context.Background(), serverID)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(clients))
	for _, c := range clients {
		names = append(names, c.Name)
	}
	return names
}

func TestDeleteClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	srv := testServer(t, s, false)
	other := testServer(t, s, false)
	removed := createTestClient(t, s, newTestClient(srv.ID, "gone", "10.66.66.2"))
	createTestClient(t, s, newTestClient(srv.ID, "kept", "10.66.66.3"))
	createTestClient(t, s, newTestClient(other.ID, "gone", "10.66.66.2"))

	if err := s.DeleteClient(ctx, removed.ID); err != nil {
		t.Fatal(err)
	}

	if got, want := clientNames(t, s, srv.ID), []string{"kept"}; !slices.Equal(got, want) {
		t.Errorf("clients = %q, want %q", got, want)
	}
	if got, want := clientNames(t, s, other.ID), []string{"gone"}; !slices.Equal(got, want) {
		t.Errorf("same name on another server: clients = %q, want %q", got, want)
	}
	var keys int
	if err := s.db.QueryRow(ctx, "select count(*) from wg_clients where client_id = $1", removed.ID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Errorf("wg_clients rows left: %d", keys)
	}
}

func TestSetClientEnabled(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	srv := testServer(t, s, false)
	other := testServer(t, s, false)
	a := createTestClient(t, s, newTestClient(srv.ID, "a", "10.66.66.2"))
	createTestClient(t, s, newTestClient(srv.ID, "b", "10.66.66.3"))
	createTestClient(t, s, newTestClient(other.ID, "a", "10.66.66.2"))

	enabled := func(serverID int64) map[string]bool {
		t.Helper()
		clients, err := s.ListClients(ctx, serverID)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, c := range clients {
			out[c.Name] = c.Enabled
		}
		return out
	}

	for _, want := range []bool{false, false, true, true} { // repeating is not an error
		if err := s.SetClientEnabled(ctx, a.ID, want); err != nil {
			t.Fatal(err)
		}
		got := enabled(srv.ID)
		if got["a"] != want {
			t.Errorf("a enabled = %v, want %v", got["a"], want)
		}
		if !got["b"] {
			t.Error("another client got disabled")
		}
		if !enabled(other.ID)["a"] {
			t.Error("same name on another server got disabled")
		}
	}
}

func TestClientNotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	srv := testServer(t, s, false)
	other := testServer(t, s, false)
	createTestClient(t, s, newTestClient(other.ID, "elsewhere", "10.66.66.2"))

	const missingID = -1
	for name, call := range map[string]func() error{
		"DeleteClient":     func() error { return s.DeleteClient(ctx, missingID) },
		"SetClientEnabled": func() error { return s.SetClientEnabled(ctx, missingID, false) },
		"GetClient": func() error {
			_, err := s.GetClient(ctx, missingID)
			return err
		},
		"GetClientByName unknown name": func() error {
			_, err := s.GetClientByName(ctx, srv.ID, "no-such-client")
			return err
		},
		"GetClientByName another server": func() error {
			_, err := s.GetClientByName(ctx, srv.ID, "elsewhere")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
	if got := clientNames(t, s, other.ID); !slices.Equal(got, []string{"elsewhere"}) {
		t.Errorf("client of another server was touched: %q", got)
	}
}

// wantSameClient compares the fields that come back from the database.
func wantSameClient(t *testing.T, got, want vpn.Client) {
	t.Helper()
	if got.ID != want.ID || got.ServerID != want.ServerID || got.Name != want.Name ||
		got.IPv4 != want.IPv4 || got.IPv6 != want.IPv6 || got.Enabled != want.Enabled ||
		!slices.Equal(got.TunnelNetworks, want.TunnelNetworks) ||
		!got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("client = %+v, want %+v", got, want)
	}
	gotWG, ok := got.Protocol.(vpn.WireGuardClient)
	if !ok {
		t.Fatalf("protocol = %T, want WireGuardClient", got.Protocol)
	}
	wantWG := want.Protocol.(vpn.WireGuardClient)
	if !slices.Equal(gotWG.PrivateKey.Bytes(), wantWG.PrivateKey.Bytes()) ||
		!slices.Equal(gotWG.PresharedKey.Bytes(), wantWG.PresharedKey.Bytes()) ||
		gotWG.PersistentKeepalive != wantWG.PersistentKeepalive {
		t.Error("WireGuard fields do not match")
	}
}

func TestGetClient(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, true)
	createTestClient(t, s, newTestClient(srv.ID, "first", "10.66.66.2", "fd42::2"))
	want := createTestClient(t, s, newTestClient(srv.ID, "second", "10.66.66.3", "fd42::3"))

	got, err := s.GetClient(context.Background(), want.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantSameClient(t, got, want)
}

func TestGetClientByName(t *testing.T) {
	s := testStore(t)
	srv := testServer(t, s, false)
	other := testServer(t, s, false)
	createTestClient(t, s, newTestClient(other.ID, "phone", "10.66.66.2"))
	want := createTestClient(t, s, newTestClient(srv.ID, "phone", "10.66.66.2"))

	got, err := s.GetClientByName(context.Background(), srv.ID, "phone")
	if err != nil {
		t.Fatal(err)
	}
	wantSameClient(t, got, want)
}

func TestCreateClientConflict(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	srv := testServer(t, s, true)
	createTestClient(t, s, newTestClient(srv.ID, "taken", "10.66.66.2", "fd42::2"))

	tests := []struct {
		name   string
		client vpn.Client
		want   error
	}{
		{"name", newTestClient(srv.ID, "taken", "10.66.66.3", "fd42::3"), ErrClientNameTaken},
		{"IPv4", newTestClient(srv.ID, "new", "10.66.66.2", "fd42::3"), ErrClientAddressTaken},
		{"IPv6", newTestClient(srv.ID, "new", "10.66.66.3", "fd42::2"), ErrClientAddressTaken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := s.CreateClient(ctx, tt.client)
			if !errors.Is(err, tt.want) {
				t.Fatalf("CreateClient() = %+v, %v; want %v", c, err, tt.want)
			}
		})
	}
	if got := clientNames(t, s, srv.ID); !slices.Equal(got, []string{"taken"}) {
		t.Errorf("clients = %q, want only the original", got)
	}
}
