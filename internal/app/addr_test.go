package app

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/uhiddename/reloc/internal/vpn"
)

func TestNextFreeAddr(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		server string
		used   []string
		want   string
	}{
		{"empty v4", "10.66.66.0/24", "10.66.66.1", nil, "10.66.66.2"},
		{"hole in the middle", "10.66.66.0/24", "10.66.66.1", []string{"10.66.66.2", "10.66.66.4"}, "10.66.66.3"},
		{"used unordered", "10.66.66.0/24", "10.66.66.1", []string{"10.66.66.3", "10.66.66.2"}, "10.66.66.4"},
		{"server not first", "10.66.66.0/24", "10.66.66.254", nil, "10.66.66.1"},
		{"skips server in the middle", "10.66.66.0/24", "10.66.66.2", []string{"10.66.66.1"}, "10.66.66.3"},
		{"last before broadcast", "10.66.66.0/30", "10.66.66.1", nil, "10.66.66.2"},
		{"unmasked prefix", "10.66.66.7/24", "10.66.66.1", nil, "10.66.66.2"},
		{"empty v6", "fd42::/64", "fd42::1", nil, "fd42::2"},
		{"v6 hole", "fd42::/64", "fd42::1", []string{"fd42::2", "fd42::4"}, "fd42::3"},
		{"v6 past hex digit", "fd42::/64", "fd42::1", rangeAddrs("fd42::2", 8), "fd42::a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextFreeAddr(testNetwork(tt.prefix, tt.server), parseAddrs(tt.used))
			if err != nil {
				t.Fatal(err)
			}
			if want := netip.MustParseAddr(tt.want); got != want {
				t.Errorf("nextFreeAddr() = %v, want %v", got, want)
			}
		})
	}
}

func TestNextFreeAddrFull(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		server string
		used   []string
	}{
		{"/30 with one client", "10.66.66.0/30", "10.66.66.1", []string{"10.66.66.2"}},
		{"/31", "10.66.66.0/31", "10.66.66.0", nil},
		{"/32", "10.66.66.1/32", "10.66.66.1", nil},
		{"/29 all used", "10.66.66.0/29", "10.66.66.1", rangeAddrs("10.66.66.2", 5)},
		{"/126 v6", "fd42::/126", "fd42::1", []string{"fd42::2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextFreeAddr(testNetwork(tt.prefix, tt.server), parseAddrs(tt.used))
			if !errors.Is(err, ErrNetworkFull) {
				t.Fatalf("nextFreeAddr() = %v, %v; want ErrNetworkFull", got, err)
			}
			if got.IsValid() {
				t.Errorf("nextFreeAddr() on error = %v, want zero", got)
			}
		})
	}
}

func testNetwork(prefix, server string) vpn.Network {
	return vpn.Network{
		Prefix: netip.MustParsePrefix(prefix),
		Addr:   netip.MustParseAddr(server),
	}
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// rangeAddrs returns n consecutive addresses starting at from.
func rangeAddrs(from string, n int) []string {
	a := netip.MustParseAddr(from)
	out := make([]string, 0, n)
	for range n {
		out = append(out, a.String())
		a = a.Next()
	}
	return out
}
