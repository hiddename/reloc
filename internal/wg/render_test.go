package wg

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files in testdata")

func TestRender(t *testing.T) {
	name, err := ParseDNSName("vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	lan, err := ParseDNSName("lan")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := EndpointFromName(name, 51820)
	if err != nil {
		t.Fatal(err)
	}

	serverInterface := Interface{
		PrivateKey: PrivateKey{1},
		Address: []netip.Prefix{
			netip.MustParsePrefix("10.66.66.1/24"),
			netip.MustParsePrefix("fd42::1/64"),
		},
		ListenPort: 51820,
		PostUp:     []string{"post-up 1", "post-up 2"},
		PostDown:   []string{"post-down 1"},
	}

	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "server",
			config: Config{
				Interface: serverInterface,
				Peers: []Peer{
					{
						PublicKey:    PublicKey{2},
						PresharedKey: PresharedKey{3},
						AllowedIPs: []netip.Prefix{
							netip.MustParsePrefix("10.66.66.2/32"),
							netip.MustParsePrefix("fd42::2/128"),
						},
					},
					{
						PublicKey:    PublicKey{4},
						PresharedKey: PresharedKey{5},
						AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.66.66.3/32")},
					},
				},
			},
		},
		{
			name:   "server-no-peers",
			config: Config{Interface: serverInterface},
		},
		{
			name: "client",
			config: Config{
				Interface: Interface{
					PrivateKey: PrivateKey{6},
					Address: []netip.Prefix{
						netip.MustParsePrefix("10.66.66.2/24"),
						netip.MustParsePrefix("fd42::2/64"),
					},
					MTU:       1420,
					DNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
					DNSSearch: []DNSName{lan},
				},
				Peers: []Peer{
					{
						PublicKey:           PublicKey{7},
						PresharedKey:        PresharedKey{3},
						AllowedIPs:          DefaultAllowedIPs(),
						Endpoint:            endpoint,
						PersistentKeepalive: DefaultPersistentKeepalive,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Render(&buf, tt.config); err != nil {
				t.Fatal(err)
			}

			golden := filepath.Join("testdata", tt.name+".conf")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("Render() mismatch with %s\ngot:\n%s\nwant:\n%s", golden, buf.Bytes(), want)
			}
		})
	}
}
