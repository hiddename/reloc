package app

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/uhiddename/reloc/internal/vpn"
)

// prodServer mirrors the wg1 server running in production, whose hooks were
// verified by hand before the generator existed.
func prodServer() vpn.Server {
	return vpn.Server{
		InterfaceName:   "wg1",
		EgressInterface: "eth0",
		ClientIsolation: true,
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.66.66.0/24"),
			Addr:   netip.MustParseAddr("10.66.66.1"),
			NAT:    true,
		},
	}
}

func TestServerHooksProduction(t *testing.T) {
	// copied verbatim from the working /etc/wireguard/wg1.conf
	wantUp := []string{
		"sysctl -w net.ipv4.ip_forward=1",
		`nft 'add table inet reloc_wg1; delete table inet reloc_wg1; table inet reloc_wg1 { chain forward { type filter hook forward priority filter; policy accept; iifname "wg1" oifname "wg1" drop; iifname "wg1" oifname "eth0" accept; iifname "eth0" oifname "wg1" ct state established,related accept; iifname "eth0" oifname "wg1" drop; }; chain postrouting { type nat hook postrouting priority srcnat; policy accept; ip saddr 10.66.66.0/24 oifname "eth0" masquerade; }; }'`,
	}
	wantDown := []string{"nft delete table inet reloc_wg1"}

	up, down := serverHooks(prodServer())
	if !slices.Equal(up, wantUp) {
		t.Errorf("PostUp mismatch\ngot:  %q\nwant: %q", up, wantUp)
	}
	if !slices.Equal(down, wantDown) {
		t.Errorf("PostDown = %q, want %q", down, wantDown)
	}
}

func TestServerHooks(t *testing.T) {
	v6 := &vpn.Network{
		Prefix: netip.MustParsePrefix("fd42::/64"),
		Addr:   netip.MustParseAddr("fd42::1"),
		NAT:    true,
	}
	tests := []struct {
		name   string
		modify func(*vpn.Server)
		// substrings that must and must not appear in the joined PostUp
		want    []string
		notWant []string
		sysctls []string
	}{
		{
			name:   "no egress matches anything but the tunnel",
			modify: func(s *vpn.Server) { s.EgressInterface = "" },
			want: []string{
				`iifname "wg1" oifname != "wg1" accept`,
				`iifname != "wg1" oifname "wg1" ct state established,related accept`,
				`iifname != "wg1" oifname "wg1" drop`,
				`ip saddr 10.66.66.0/24 oifname != "wg1" masquerade`,
			},
			notWant: []string{`""`, `"!=`},
			sysctls: []string{"sysctl -w net.ipv4.ip_forward=1"},
		},
		{
			name:    "no isolation",
			modify:  func(s *vpn.Server) { s.ClientIsolation = false },
			want:    []string{`iifname "wg1" oifname "wg1" accept`},
			notWant: []string{`iifname "wg1" oifname "wg1" drop`},
			sysctls: []string{"sysctl -w net.ipv4.ip_forward=1"},
		},
		{
			name:    "no NAT keeps an empty postrouting chain",
			modify:  func(s *vpn.Server) { s.IPv4.NAT = false },
			want:    []string{"chain postrouting { type nat hook postrouting priority srcnat; policy accept; }"},
			notWant: []string{"masquerade"},
			sysctls: []string{"sysctl -w net.ipv4.ip_forward=1"},
		},
		{
			name:   "dual stack with NAT",
			modify: func(s *vpn.Server) { s.IPv6 = v6 },
			want: []string{
				`ip saddr 10.66.66.0/24 oifname "eth0" masquerade`,
				`ip6 saddr fd42::/64 oifname "eth0" masquerade`,
			},
			sysctls: []string{
				"sysctl -w net.ipv4.ip_forward=1",
				"sysctl -w net.ipv6.conf.all.forwarding=1",
			},
		},
		{
			name: "NAT only for IPv4",
			modify: func(s *vpn.Server) {
				v := *v6
				v.NAT = false
				s.IPv6 = &v
			},
			want:    []string{`ip saddr 10.66.66.0/24 oifname "eth0" masquerade`},
			notWant: []string{"ip6 saddr"},
			sysctls: []string{
				"sysctl -w net.ipv4.ip_forward=1",
				"sysctl -w net.ipv6.conf.all.forwarding=1",
			},
		},
		{
			name: "IPv6 only",
			modify: func(s *vpn.Server) {
				s.IPv4 = nil
				s.IPv6 = v6
			},
			want:    []string{`ip6 saddr fd42::/64 oifname "eth0" masquerade`},
			notWant: []string{"ip saddr", "ipv4"},
			sysctls: []string{"sysctl -w net.ipv6.conf.all.forwarding=1"},
		},
		{
			name:   "interface name goes into the table name",
			modify: func(s *vpn.Server) { s.InterfaceName = "vpn-home" },
			want: []string{
				"add table inet reloc_vpn-home; delete table inet reloc_vpn-home; table inet reloc_vpn-home {",
				`iifname "vpn-home" oifname "vpn-home" drop`,
			},
			sysctls: []string{"sysctl -w net.ipv4.ip_forward=1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serv := prodServer()
			tt.modify(&serv)
			up, down := serverHooks(serv)

			if len(up) != len(tt.sysctls)+1 {
				t.Fatalf("PostUp has %d commands, want %d sysctls + nft:\n%q", len(up), len(tt.sysctls), up)
			}
			if got := up[:len(up)-1]; !slices.Equal(got, tt.sysctls) {
				t.Errorf("sysctls = %q, want %q", got, tt.sysctls)
			}
			nft := up[len(up)-1]
			if !strings.HasPrefix(nft, "nft '") || !strings.HasSuffix(nft, "; }; }'") {
				t.Errorf("nft command is not a quoted one-line ruleset: %s", nft)
			}
			if strings.Count(nft, "'") != 2 {
				t.Errorf("nft command must contain exactly two single quotes: %s", nft)
			}
			for _, s := range tt.want {
				if !strings.Contains(nft, s) {
					t.Errorf("PostUp lacks %q:\n%s", s, nft)
				}
			}
			for _, s := range tt.notWant {
				if strings.Contains(nft, s) {
					t.Errorf("PostUp contains %q:\n%s", s, nft)
				}
			}
			wantDown := "nft delete table inet reloc_" + serv.InterfaceName
			if !slices.Equal(down, []string{wantDown}) {
				t.Errorf("PostDown = %q, want [%q]", down, wantDown)
			}
		})
	}
}
