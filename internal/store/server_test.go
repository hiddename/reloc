package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

var testHostSeq atomic.Int64

// testHost creates a host with a unique name, so a test can create several.
func testHost(t *testing.T, s *Store) vpn.Host {
	t.Helper()
	return createTestHost(t, s, vpn.Host{
		Name: fmt.Sprintf("store/%s-%d", t.Name(), testHostSeq.Add(1)),
		SSH: vpn.SSH{
			Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("192.0.2.1"), 22),
			User:    "root",
			HostKey: testHostKey(t),
		},
	})
}

// createTestServer creates a server and deletes it when the test ends.
// Cleanups run in reverse order, so the server is deleted before its host.
func createTestServer(t *testing.T, s *Store, srv vpn.Server) vpn.Server {
	t.Helper()
	got, err := s.CreateServer(context.Background(), srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.db.Exec(context.Background(), "delete from vpn_servers where id = $1", got.ID); err != nil {
			t.Error(err)
		}
	})
	return got
}

type serverDBRow struct {
	protocol      string
	transport     string
	interfaceName string
	listenPort    int32
	endpointAddr  *netip.Addr
	endpointName  *string
	endpointPort  *int32
	ipv4Network   *netip.Prefix
	ipv6Network   *netip.Prefix
	ipv4Address   *netip.Addr
	ipv6Address   *netip.Addr
	natIPv4       bool
	natIPv6       bool
	egress        *string
	isolation     bool
	dnsServers    []netip.Addr
	dnsSearch     []string
	privateKey    []byte
	publicKey     []byte
	mtu           *int16
	clientMTU     *int16
}

func readServerRow(t *testing.T, s *Store, id int64) serverDBRow {
	t.Helper()
	var r serverDBRow
	err := s.db.QueryRow(context.Background(), `
select v.protocol, v.transport, v.interface_name, v.listen_port,
       v.endpoint_addr, v.endpoint_name, v.endpoint_port,
       v.ipv4_network, v.ipv6_network, v.ipv4_address, v.ipv6_address,
       v.nat_ipv4, v.nat_ipv6, v.egress_interface, v.client_isolation,
       v.client_dns_servers::inet[], v.client_dns_search::text[],
       w.private_key, w.public_key, w.mtu, w.client_mtu
from vpn_servers v join wg_servers w on w.server_id = v.id
where v.id = $1`, id).Scan(
		&r.protocol, &r.transport, &r.interfaceName, &r.listenPort,
		&r.endpointAddr, &r.endpointName, &r.endpointPort,
		&r.ipv4Network, &r.ipv6Network, &r.ipv4Address, &r.ipv6Address,
		&r.natIPv4, &r.natIPv6, &r.egress, &r.isolation,
		&r.dnsServers, &r.dnsSearch,
		&r.privateKey, &r.publicKey, &r.mtu, &r.clientMTU,
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCreateServerDualStack(t *testing.T) {
	s := testStore(t)
	h := testHost(t, s)
	key := wg.Genkey()

	srv := createTestServer(t, s, vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.66.66.0/24"),
			Addr:   netip.MustParseAddr("10.66.66.1"),
			NAT:    true,
		},
		IPv6: &vpn.Network{
			Prefix: netip.MustParsePrefix("fd42::/64"),
			Addr:   netip.MustParseAddr("fd42::1"),
			NAT:    false,
		},
		ClientIsolation: true,
		Protocol:        vpn.WireGuardServer{PrivateKey: key},
	})
	if srv.ID == 0 || srv.CreatedAt.IsZero() {
		t.Fatalf("ID or CreatedAt not set: %+v", srv)
	}

	r := readServerRow(t, s, srv.ID)
	if r.protocol != "wireguard" || r.transport != "udp" || r.interfaceName != "wg0" || r.listenPort != 51820 {
		t.Errorf("protocol/transport/interface/port = %s/%s/%s/%d", r.protocol, r.transport, r.interfaceName, r.listenPort)
	}
	if r.endpointAddr == nil || *r.endpointAddr != netip.MustParseAddr("198.51.100.7") || r.endpointName != nil {
		t.Errorf("endpoint addr/name = %v/%v", deref(r.endpointAddr), deref(r.endpointName))
	}
	if r.endpointPort != nil {
		t.Errorf("endpoint_port = %d, want NULL when equal to listen_port", *r.endpointPort)
	}
	if r.ipv4Network == nil || *r.ipv4Network != netip.MustParsePrefix("10.66.66.0/24") {
		t.Errorf("ipv4_network = %v", deref(r.ipv4Network))
	}
	if r.ipv4Address == nil || *r.ipv4Address != netip.MustParseAddr("10.66.66.1") {
		t.Errorf("ipv4_address = %v", deref(r.ipv4Address))
	}
	if r.ipv6Network == nil || *r.ipv6Network != netip.MustParsePrefix("fd42::/64") {
		t.Errorf("ipv6_network = %v", deref(r.ipv6Network))
	}
	if r.ipv6Address == nil || *r.ipv6Address != netip.MustParseAddr("fd42::1") {
		t.Errorf("ipv6_address = %v", deref(r.ipv6Address))
	}
	if !r.natIPv4 || r.natIPv6 {
		t.Errorf("nat_ipv4/nat_ipv6 = %v/%v, want true/false", r.natIPv4, r.natIPv6)
	}
	if r.egress != nil {
		t.Errorf("egress_interface = %q, want NULL", *r.egress)
	}
	if !r.isolation {
		t.Error("client_isolation = false, want true")
	}
	if r.dnsServers == nil || len(r.dnsServers) != 0 || r.dnsSearch == nil || len(r.dnsSearch) != 0 {
		t.Errorf("client_dns_servers/search = %v/%v, want empty arrays", r.dnsServers, r.dnsSearch)
	}
	if !slices.Equal(r.privateKey, key.Bytes()) || !slices.Equal(r.publicKey, key.PublicKey().Bytes()) {
		t.Error("private_key or public_key does not match")
	}
	if r.mtu != nil || r.clientMTU != nil {
		t.Errorf("mtu/client_mtu = %v/%v, want NULL", deref(r.mtu), deref(r.clientMTU))
	}
}

func TestCreateServerIPv4Only(t *testing.T) {
	s := testStore(t)
	h := testHost(t, s)

	srv := createTestServer(t, s, vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg1",
		ListenPort:    51821,
		Endpoint:      must(inet.EndpointFromName(inet.MustParseDNSName("vpn.example.com"), 443)),
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.77.0.0/16"),
			Addr:   netip.MustParseAddr("10.77.0.1"),
			NAT:    true,
		},
		EgressInterface: "eth0",
		ClientDNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		ClientDNSSearch: []inet.DNSName{inet.MustParseDNSName("lan")},
		Protocol:        vpn.WireGuardServer{PrivateKey: wg.Genkey(), MTU: 1420, ClientMTU: 1380},
	})

	r := readServerRow(t, s, srv.ID)
	if r.endpointAddr != nil || r.endpointName == nil || *r.endpointName != "vpn.example.com" {
		t.Errorf("endpoint addr/name = %v/%v", deref(r.endpointAddr), deref(r.endpointName))
	}
	if r.endpointPort == nil || *r.endpointPort != 443 {
		t.Errorf("endpoint_port = %v, want 443", deref(r.endpointPort))
	}
	if r.ipv6Network != nil || r.ipv6Address != nil || r.natIPv6 {
		t.Errorf("ipv6 = %v/%v/%v, want NULL/NULL/false", deref(r.ipv6Network), deref(r.ipv6Address), r.natIPv6)
	}
	if r.egress == nil || *r.egress != "eth0" {
		t.Errorf("egress_interface = %v, want eth0", deref(r.egress))
	}
	if !slices.Equal(r.dnsServers, []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}) {
		t.Errorf("client_dns_servers = %v", r.dnsServers)
	}
	if !slices.Equal(r.dnsSearch, []string{"lan"}) {
		t.Errorf("client_dns_search = %v", r.dnsSearch)
	}
	if r.mtu == nil || *r.mtu != 1420 || r.clientMTU == nil || *r.clientMTU != 1380 {
		t.Errorf("mtu/client_mtu = %v/%v, want 1420/1380", deref(r.mtu), deref(r.clientMTU))
	}
}

func TestCreateServerNoProtocol(t *testing.T) {
	s := &Store{} // never reaches the database
	srv, err := s.CreateServer(context.Background(), vpn.Server{InterfaceName: "wg0"})
	if err == nil {
		t.Fatal("CreateServer() without protocol succeeded")
	}
	if srv.InterfaceName != "" {
		t.Errorf("CreateServer() on error = %+v, want zero", srv)
	}
}

func TestCreateServerRollback(t *testing.T) {
	s := testStore(t)
	h := testHost(t, s)
	ctx := context.Background()

	_, err := s.CreateServer(ctx, vpn.Server{
		HostID:        h.ID,
		Transport:     vpn.UDP,
		InterfaceName: "wg0",
		ListenPort:    51820,
		Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
		IPv4: &vpn.Network{
			Prefix: netip.MustParsePrefix("10.66.66.0/24"),
			Addr:   netip.MustParseAddr("10.66.66.1"),
		},
		// rejected by the inet_mtu domain in wg_servers, after the vpn_servers insert
		Protocol: vpn.WireGuardServer{PrivateKey: wg.Genkey(), MTU: 1000},
	})
	if err == nil {
		t.Fatal("CreateServer() with invalid MTU succeeded")
	}

	var n int
	if err := s.db.QueryRow(ctx, "select count(*) from vpn_servers where host_id = $1", h.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("vpn_servers row left after failed insert: count = %d", n)
	}
}

func TestGetServer(t *testing.T) {
	s := testStore(t)

	tests := []struct {
		name string
		srv  vpn.Server
	}{
		{
			name: "dual stack, endpoint by address, defaults",
			srv: vpn.Server{
				Transport:     vpn.UDP,
				InterfaceName: "wg0",
				ListenPort:    51820,
				Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("198.51.100.7"), 51820),
				IPv4: &vpn.Network{
					Prefix: netip.MustParsePrefix("10.66.66.0/24"),
					Addr:   netip.MustParseAddr("10.66.66.1"),
					NAT:    true,
				},
				IPv6: &vpn.Network{
					Prefix: netip.MustParsePrefix("fd42::/64"),
					Addr:   netip.MustParseAddr("fd42::1"),
				},
				ClientIsolation: true,
				Protocol:        vpn.WireGuardServer{PrivateKey: wg.Genkey()},
			},
		},
		{
			name: "v4 only, endpoint by name with own port, everything set",
			srv: vpn.Server{
				Transport:       vpn.UDP,
				InterfaceName:   "wg1",
				ListenPort:      51821,
				Endpoint:        must(inet.EndpointFromName(inet.MustParseDNSName("vpn.example.com"), 443)),
				IPv4:            &vpn.Network{Prefix: netip.MustParsePrefix("10.77.0.0/16"), Addr: netip.MustParseAddr("10.77.0.1"), NAT: true},
				EgressInterface: "eth0",
				ClientDNS:       []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
				ClientDNSSearch: []inet.DNSName{inet.MustParseDNSName("lan")},
				Protocol:        vpn.WireGuardServer{PrivateKey: wg.Genkey(), MTU: 1420, ClientMTU: 1380},
			},
		},
		{
			name: "v6 only",
			srv: vpn.Server{
				Transport:     vpn.UDP,
				InterfaceName: "wg2",
				ListenPort:    51822,
				Endpoint:      inet.MustEndpointFromAddr(netip.MustParseAddr("2001:db8::7"), 51822),
				IPv6: &vpn.Network{
					Prefix: netip.MustParsePrefix("fd43::/64"),
					Addr:   netip.MustParseAddr("fd43::1"),
					NAT:    true,
				},
				Protocol: vpn.WireGuardServer{PrivateKey: wg.Genkey()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.srv.HostID = testHost(t, s).ID
			want := createTestServer(t, s, tt.srv)

			got, err := s.GetServer(context.Background(), want.ID)
			if err != nil {
				t.Fatal(err)
			}

			// the database stores no DNS as empty arrays, not NULL
			if want.ClientDNS == nil {
				want.ClientDNS = []netip.Addr{}
			}
			if want.ClientDNSSearch == nil {
				want.ClientDNSSearch = []inet.DNSName{}
			}
			if !got.CreatedAt.Equal(want.CreatedAt) {
				t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
			}
			got.CreatedAt, want.CreatedAt = time.Time{}, time.Time{}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("GetServer() mismatch\ngot:  %s\nwant: %s", dumpServer(got), dumpServer(want))
			}
		})
	}
}

func TestGetServerNotFound(t *testing.T) {
	s := testStore(t)
	_, err := s.GetServer(context.Background(), -1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetServer() err = %v, want ErrNotFound", err)
	}
}

func dumpServer(srv vpn.Server) string {
	return fmt.Sprintf("%+v ipv4=%+v ipv6=%+v", srv, deref(srv.IPv4), deref(srv.IPv6))
}
