package app

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

var update = flag.Bool("update", false, "update golden files in testdata")

func testServer() vpn.Server {
	return vpn.Server{
		ID:            1,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      must(inet.EndpointFromName(inet.MustParseDNSName("vpn.example.com"), 51820)),
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.66.66.0/24"),
			Addr:   netip.MustParseAddr("10.66.66.1"),
			NAT:    true,
		},
		IPv6: &vpn.Network{
			Prefix: netip.MustParsePrefix("fd42::/64"),
			Addr:   netip.MustParseAddr("fd42::1"),
		},
		ClientDNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		ClientDNSSearch: []inet.DNSName{inet.MustParseDNSName("lan")},
		Protocol:        vpn.WireGuardServer{PrivateKey: wg.PrivateKey{0, 1}, MTU: 1420, ClientMTU: 1380},
	}
}

func testClient(id int64, name string, key byte, addrs ...string) vpn.Client {
	c := vpn.Client{
		ID:             id,
		ServerID:       1,
		Name:           name,
		TunnelNetworks: wg.DefaultAllowedIPs(),
		Enabled:        true,
		Protocol: vpn.WireGuardClient{
			// key goes into byte 1: clamping clears the low bits of byte 0,
			// so keys that differ only there share a public key
			PrivateKey:          wg.PrivateKey{0, key},
			PresharedKey:        wg.PresharedKey{key + 100},
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

func TestServerConfig(t *testing.T) {
	disabled := testClient(12, "disabled", 12, "10.66.66.12", "fd42::12")
	disabled.Enabled = false

	tests := []struct {
		name    string
		clients []vpn.Client
	}{
		{
			name: "server",
			clients: []vpn.Client{
				testClient(10, "phone", 10, "10.66.66.10", "fd42::10"),
				testClient(11, "v4-only", 11, "10.66.66.11"),
				disabled,
			},
		},
		{
			name: "server-no-clients",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ServerConfig(testServer(), tt.clients)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, tt.name, cfg)
		})
	}
}

func TestServerConfigErrors(t *testing.T) {
	noProtocol := testServer()
	noProtocol.Protocol = nil

	otherServer := testClient(10, "phone", 10, "10.66.66.10", "fd42::10")
	otherServer.ServerID = 2

	otherServerDisabled := otherServer
	otherServerDisabled.Enabled = false

	clientNoProtocol := testClient(10, "phone", 10, "10.66.66.10", "fd42::10")
	clientNoProtocol.Protocol = nil

	tests := []struct {
		name    string
		srv     vpn.Server
		clients []vpn.Client
	}{
		{"server without protocol", noProtocol, nil},
		{"client of another server", testServer(), []vpn.Client{otherServer}},
		{"disabled client of another server", testServer(), []vpn.Client{otherServerDisabled}},
		{"client without protocol", testServer(), []vpn.Client{clientNoProtocol}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ServerConfig(tt.srv, tt.clients); err == nil {
				t.Fatal("ServerConfig() succeeded")
			}
		})
	}
}

// checkGolden renders cfg and compares it with testdata/<name>.conf.
// Run with -update to rewrite the golden files.
func checkGolden(t *testing.T, name string, cfg wg.Config) {
	t.Helper()
	var buf bytes.Buffer
	if err := wg.Render(&buf, cfg); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", name+".conf")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("config mismatch with %s\ngot:\n%s\nwant:\n%s", golden, buf.Bytes(), want)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestClientConfig(t *testing.T) {
	split := testClient(11, "split", 11, "10.66.66.11")
	split.TunnelNetworks = []netip.Prefix{netip.MustParsePrefix("10.66.66.0/24")}
	p := split.Protocol.(vpn.WireGuardClient)
	p.PersistentKeepalive = 0
	split.Protocol = p

	tests := []struct {
		name   string
		client vpn.Client
	}{
		{"client", testClient(10, "phone", 10, "10.66.66.10", "fd42::10")},
		{"client-split-v4-only", split},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ClientConfig(testServer(), tt.client)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, tt.name, cfg)
		})
	}
}

func TestClientConfigErrors(t *testing.T) {
	noProtocol := testServer()
	noProtocol.Protocol = nil

	otherServer := testClient(10, "phone", 10, "10.66.66.10", "fd42::10")
	otherServer.ServerID = 2

	clientNoProtocol := testClient(10, "phone", 10, "10.66.66.10", "fd42::10")
	clientNoProtocol.Protocol = nil

	tests := []struct {
		name   string
		srv    vpn.Server
		client vpn.Client
	}{
		{"server without protocol", noProtocol, testClient(10, "phone", 10, "10.66.66.10")},
		{"client of another server", testServer(), otherServer},
		{"client without protocol", testServer(), clientNoProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ClientConfig(tt.srv, tt.client); err == nil {
				t.Fatal("ClientConfig() succeeded")
			}
		})
	}
}
