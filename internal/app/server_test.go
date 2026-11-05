package app

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/uhiddename/reloc/internal/store"
)

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
