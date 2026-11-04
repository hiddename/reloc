package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

const (
	insertVPNServerSQL = `
insert into vpn_servers (host_id, protocol, transport, interface_name, listen_port, endpoint_addr, endpoint_name, endpoint_port, ipv4_network, ipv6_network, ipv4_address, ipv6_address, nat_ipv4, nat_ipv6, egress_interface, client_isolation, client_dns_servers, client_dns_search)
values (@host_id, @protocol, @transport, @interface_name, @listen_port, @endpoint_addr, @endpoint_name, @endpoint_port, @ipv4_network, @ipv6_network, @ipv4_address, @ipv6_address, @nat_ipv4, @nat_ipv6, @egress_interface, @client_isolation, @client_dns_servers, @client_dns_search)
returning id, created_at
`
	insertWGServerSQL = `
insert into wg_servers (server_id, private_key, public_key, mtu, client_mtu)
values (@server_id, @private_key, @public_key, @mtu, @client_mtu)
`
)

func (s *Store) CreateServer(ctx context.Context, serv vpn.Server) (vpn.Server, error) {
	serv, err := s.createServer(ctx, serv)
	if err != nil {
		return vpn.Server{}, fmt.Errorf("store: create server: %w", err)
	}
	return serv, nil
}

func (s *Store) createServer(ctx context.Context, serv vpn.Server) (vpn.Server, error) {
	var zero vpn.Server
	if serv.Protocol == nil {
		return zero, errors.New("protocol is not set")
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		ipv4Network, ipv4Addr, ipv4Nat := networkToTuple(serv.IPv4)
		ipv6Network, ipv6Addr, ipv6Nat := networkToTuple(serv.IPv6)
		args := pgx.NamedArgs{
			"host_id":            serv.HostID,
			"protocol":           serv.Protocol.Name(),
			"transport":          serv.Transport,
			"interface_name":     serv.InterfaceName,
			"listen_port":        serv.ListenPort,
			"endpoint_addr":      nilIfZero(serv.Endpoint.Addr()),
			"endpoint_name":      nilIfZero(serv.Endpoint.Name()),
			"endpoint_port":      nilIf(serv.Endpoint.Port(), serv.Endpoint.Port() == serv.ListenPort),
			"ipv4_network":       ipv4Network,
			"ipv6_network":       ipv6Network,
			"ipv4_address":       ipv4Addr,
			"ipv6_address":       ipv6Addr,
			"nat_ipv4":           ipv4Nat,
			"nat_ipv6":           ipv6Nat,
			"egress_interface":   nilIfZero(serv.EgressInterface),
			"client_isolation":   serv.ClientIsolation,
			"client_dns_servers": emptyIfNil(serv.ClientDNS),
			"client_dns_search":  emptyIfNil(mapSlice(serv.ClientDNSSearch, inet.DNSName.String)),
		}
		err := tx.QueryRow(ctx, insertVPNServerSQL, args).
			Scan(&serv.ID, &serv.CreatedAt)
		if err != nil {
			return err
		}

		switch p := serv.Protocol.(type) {
		case vpn.WireGuardServer:
			args = pgx.NamedArgs{
				"server_id":   serv.ID,
				"private_key": p.PrivateKey.Bytes(),
				"public_key":  p.PrivateKey.PublicKey().Bytes(),
				"mtu":         nilIfZero(p.MTU),
				"client_mtu":  nilIfZero(p.ClientMTU),
			}
			if _, err = tx.Exec(ctx, insertWGServerSQL, args); err != nil {
				return err
			}
		case nil:
			return fmt.Errorf("%w: %T", ErrUnsupportedProtocol, serv.Protocol)
		default:
			return fmt.Errorf("%w: %v", ErrUnsupportedProtocol, serv.Protocol.Name())
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	return serv, nil
}

const selectServerSQL = `
select
	s.id, s.host_id, s.protocol, s.transport, s.interface_name, s.listen_port,
	s.endpoint_addr, s.endpoint_name, coalesce(s.endpoint_port, s.listen_port) as endpoint_port,
	s.ipv4_network, s.ipv6_network, s.ipv4_address, s.ipv6_address, s.nat_ipv4, s.nat_ipv6,
	s.egress_interface, s.client_isolation, s.client_dns_servers, s.client_dns_search, s.created_at,
	wgs.private_key as wgs_private_key, wgs.mtu as wgs_mtu, wgs.client_mtu as wgs_client_mtu
from vpn_servers s
left join wg_servers wgs on wgs.server_id = s.id
where s.id = @id
`

type serverRow struct {
	ID                        int64         `db:"id"`
	HostID                    int64         `db:"host_id"`
	Protocol                  string        `db:"protocol"`
	Transport                 string        `db:"transport"`
	InterfaceName             string        `db:"interface_name"`
	ListenPort                int32         `db:"listen_port"`
	EndpointAddr              *netip.Addr   `db:"endpoint_addr"`
	EndpointName              *string       `db:"endpoint_name"`
	EndpointPort              int32         `db:"endpoint_port"`
	IPv4Network               *netip.Prefix `db:"ipv4_network"`
	IPv6Network               *netip.Prefix `db:"ipv6_network"`
	IPv4Address               *netip.Addr   `db:"ipv4_address"`
	IPv6Address               *netip.Addr   `db:"ipv6_address"`
	NATIPv4                   bool          `db:"nat_ipv4"`
	NATIPv6                   bool          `db:"nat_ipv6"`
	EgressInterface           *string       `db:"egress_interface"`
	ClientIsolation           bool          `db:"client_isolation"`
	ClientDNSServers          []netip.Addr  `db:"client_dns_servers"`
	ClientDNSSearch           []string      `db:"client_dns_search"`
	CreatedAt                 time.Time     `db:"created_at"`
	WireGuardServerPrivateKey []byte        `db:"wgs_private_key"`
	WireGuardServerMTU        *int16        `db:"wgs_mtu"`
	WireGuardServerClientMTU  *int16        `db:"wgs_client_mtu"`
}

func (r serverRow) wireGuard() (vpn.WireGuardServer, error) {
	wgPrivateKey, err := wg.KeyFromBytes[wg.PrivateKey](r.WireGuardServerPrivateKey)
	if err != nil {
		return vpn.WireGuardServer{}, err
	}
	return vpn.WireGuardServer{
		PrivateKey: wgPrivateKey,
		MTU:        uint16(zeroIfNil(r.WireGuardServerMTU)),
		ClientMTU:  uint16(zeroIfNil(r.WireGuardServerClientMTU)),
	}, nil
}

func (r serverRow) server() (vpn.Server, error) {
	var zero vpn.Server
	transport, err := vpn.ParseTransport(r.Transport)
	if err != nil {
		return zero, err
	}
	protocolName, err := vpn.ParseProtocol(r.Protocol)
	if err != nil {
		return zero, err
	}
	var protocol vpn.ServerProtocol
	switch protocolName {
	case vpn.WireGuard:
		if protocol, err = r.wireGuard(); err != nil {
			return zero, err
		}
	default:
		return zero, fmt.Errorf("%w: %v", ErrUnsupportedProtocol, protocolName)
	}
	endpoint, err := endpointFromTuple(r.EndpointAddr, r.EndpointName, r.EndpointPort)
	if err != nil {
		return zero, err
	}
	clientDNSSearch, err := mapSliceErr(r.ClientDNSSearch, inet.ParseDNSName)
	if err != nil {
		return zero, err
	}
	return vpn.Server{
		ID:              r.ID,
		HostID:          r.HostID,
		Transport:       transport,
		InterfaceName:   r.InterfaceName,
		ListenPort:      uint16(r.ListenPort),
		Endpoint:        endpoint,
		IPv4:            networkFromTuple(r.IPv4Network, r.IPv4Address, r.NATIPv4),
		IPv6:            networkFromTuple(r.IPv6Network, r.IPv6Address, r.NATIPv6),
		EgressInterface: zeroIfNil(r.EgressInterface),
		ClientIsolation: r.ClientIsolation,
		ClientDNS:       r.ClientDNSServers,
		ClientDNSSearch: clientDNSSearch,
		Protocol:        protocol,
		CreatedAt:       r.CreatedAt,
	}, nil
}

func (s *Store) GetServer(ctx context.Context, id int64) (vpn.Server, error) {
	server, err := s.getServer(ctx, id)
	if err != nil {
		return vpn.Server{}, fmt.Errorf("store: get server: %w", err)
	}
	return server, nil
}

func (s *Store) getServer(ctx context.Context, id int64) (vpn.Server, error) {
	var zero vpn.Server
	rows, err := s.db.Query(ctx, selectServerSQL, pgx.NamedArgs{"id": id})
	if err != nil {
		return zero, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[serverRow])
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return zero, fmt.Errorf("%w: server id %v", ErrNotFound, id)
	case err != nil:
		return zero, err
	}
	return row.server()
}
