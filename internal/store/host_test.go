package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// createTestHost creates a host and deletes it when the test ends.
func createTestHost(t *testing.T, s *Store, h vpn.Host) vpn.Host {
	t.Helper()
	got, err := s.CreateHost(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.db.Exec(context.Background(), "delete from hosts where id = $1", got.ID); err != nil {
			t.Error(err)
		}
	})
	return got
}

func TestCreateHost(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	tests := []struct {
		name     string
		addr     inet.Endpoint
		wantAddr *netip.Addr
		wantName *string
	}{
		{
			name:     "by address",
			addr:     inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 2222),
			wantAddr: new(netip.MustParseAddr("192.0.2.1")),
		},
		{
			name:     "by name",
			addr:     must(inet.EndpointFromName(inet.MustParseDNSName("vpn.example.com"), 22)),
			wantName: new("vpn.example.com"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := testHostKey(t)
			in := vpn.Host{
				Name: t.Name(),
				SSH:  vpn.SSH{Addr: tt.addr, User: "deploy", HostKey: key},
			}
			before := time.Now()
			h := createTestHost(t, s, in)

			if h.ID == 0 {
				t.Error("ID is not set")
			}
			if h.CreatedAt.Before(before.Add(-time.Minute)) || h.CreatedAt.After(time.Now().Add(time.Minute)) {
				t.Errorf("CreatedAt = %v, want about %v", h.CreatedAt, before)
			}
			if h.Name != in.Name || h.SSH.Addr != in.SSH.Addr || h.SSH.User != in.SSH.User {
				t.Errorf("CreateHost() = %+v, want input fields unchanged %+v", h, in)
			}

			var (
				addr     *netip.Addr
				name     *string
				port     int32
				username string
				hostKey  []byte
			)
			err := s.db.QueryRow(ctx,
				"select ssh_addr, ssh_name, port, username, host_key from host_ssh where host_id = $1",
				h.ID,
			).Scan(&addr, &name, &port, &username, &hostKey)
			if err != nil {
				t.Fatal(err)
			}
			if !equalPtr(addr, tt.wantAddr) {
				t.Errorf("ssh_addr = %v, want %v", deref(addr), deref(tt.wantAddr))
			}
			if !equalPtr(name, tt.wantName) {
				t.Errorf("ssh_name = %v, want %v", deref(name), deref(tt.wantName))
			}
			if port != int32(tt.addr.Port()) {
				t.Errorf("port = %d, want %d", port, tt.addr.Port())
			}
			if username != "deploy" {
				t.Errorf("username = %q, want %q", username, "deploy")
			}
			if !bytes.Equal(hostKey, key.Marshal()) {
				t.Error("host_key does not match")
			}
		})
	}
}

func TestCreateHostDuplicateName(t *testing.T) {
	s := testStore(t)
	in := vpn.Host{
		Name: t.Name(),
		SSH: vpn.SSH{
			Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 22),
			User:    "root",
			HostKey: testHostKey(t),
		},
	}
	createTestHost(t, s, in)

	h, err := s.CreateHost(context.Background(), in)
	if err == nil {
		t.Fatalf("CreateHost() with duplicate name succeeded: %+v", h)
	}
	if h != (vpn.Host{}) {
		t.Errorf("CreateHost() on error = %+v, want zero", h)
	}
}

func TestCreateHostRollback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := vpn.Host{
		Name: t.Name(),
		SSH: vpn.SSH{
			Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 22),
			User:    "Not Valid", // rejected by host_ssh check, after hosts insert
			HostKey: testHostKey(t),
		},
	}
	if _, err := s.CreateHost(ctx, in); err == nil {
		t.Fatal("CreateHost() with invalid username succeeded")
	}

	var n int
	if err := s.db.QueryRow(ctx, "select count(*) from hosts where name = $1", in.Name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("hosts row left after failed insert: count = %d", n)
	}
}

func TestCreateHostNoKey(t *testing.T) {
	s := &Store{} // never reaches the database
	_, err := s.CreateHost(context.Background(), vpn.Host{Name: "x"})
	if err == nil {
		t.Fatal("CreateHost() without host key succeeded")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func equalPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestGetHost(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	getters := []struct {
		name string
		get  func(vpn.Host) (vpn.Host, error)
	}{
		{"GetHost", func(h vpn.Host) (vpn.Host, error) { return s.GetHost(ctx, h.ID) }},
		{"GetHostByName", func(h vpn.Host) (vpn.Host, error) { return s.GetHostByName(ctx, h.Name) }},
	}
	addrs := []struct {
		name string
		addr inet.Endpoint
	}{
		{"by address", inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 2222)},
		{"by name", must(inet.EndpointFromName(inet.MustParseDNSName("vpn.example.com"), 22))},
	}
	for _, g := range getters {
		for _, tt := range addrs {
			t.Run(g.name+"/"+tt.name, func(t *testing.T) {
				want := createTestHost(t, s, vpn.Host{
					Name: t.Name(),
					SSH:  vpn.SSH{Addr: tt.addr, User: "deploy", HostKey: testHostKey(t)},
				})
				// another host, so that a wrong where clause is caught
				createTestHost(t, s, vpn.Host{
					Name: t.Name() + "-other",
					SSH:  vpn.SSH{Addr: tt.addr, User: "root", HostKey: testHostKey(t)},
				})

				got, err := g.get(want)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.SSH.HostKey.Marshal(), want.SSH.HostKey.Marshal()) {
					t.Error("host key does not match")
				}
				if !got.CreatedAt.Equal(want.CreatedAt) {
					t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
				}
				got.SSH.HostKey, want.SSH.HostKey = nil, nil
				got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
				if got != want {
					t.Errorf("%s() = %+v, want %+v", g.name, got, want)
				}
			})
		}
	}
}

func TestGetHostNotFound(t *testing.T) {
	s := testStore(t)
	h, err := s.GetHost(context.Background(), -1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if h != (vpn.Host{}) {
		t.Errorf("GetHost() on error = %+v, want zero", h)
	}
}

func TestGetHostByNameNotFound(t *testing.T) {
	s := testStore(t)
	h, err := s.GetHostByName(context.Background(), "no-such-host")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if h != (vpn.Host{}) {
		t.Errorf("GetHostByName() on error = %+v, want zero", h)
	}
}
