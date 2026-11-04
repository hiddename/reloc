package vpn

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/wg"
)

const (
	WireGuardDefaultListenPort = 51820
	WireGuardDefaultMTU        = 1420
	WireGuardDefaultClientMTU  = 1380
)

type ServerProtocol interface {
	Name() Protocol
	isServerProtocol()
}

type Server struct {
	ID              int64
	HostID          int64
	Transport       Transport
	InterfaceName   string
	ListenPort      uint16
	Endpoint        inet.Endpoint
	IPv4            *Network
	IPv6            *Network
	EgressInterface string
	ClientIsolation bool
	ClientDNS       []netip.Addr
	ClientDNSSearch []inet.DNSName
	Protocol        ServerProtocol
	CreatedAt       time.Time
}

func (s Server) WireGuard() (WireGuardServer, error) {
	p, ok := s.Protocol.(WireGuardServer)
	if !ok {
		return WireGuardServer{}, fmt.Errorf(
			"vpn: server %d: protocol is %T, want %v",
			s.ID, s.Protocol, WireGuard,
		)
	}
	return p, nil
}

type Network struct {
	Prefix netip.Prefix
	Addr   netip.Addr
	NAT    bool
}

func ParseNetwork(s string) (*Network, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, fmt.Errorf("vpn: parse network: %w", err)
	}
	if p.Addr() == p.Masked().Addr() {
		return nil, fmt.Errorf("vpn: parse network %q: want the server address, not the network address", s)
	}
	return &Network{
		Prefix: p.Masked(),
		Addr:   p.Addr(),
	}, nil
}

type WireGuardServer struct {
	PrivateKey wg.PrivateKey
	MTU        uint16
	ClientMTU  uint16
}

var _ ServerProtocol = WireGuardServer{}

func (WireGuardServer) Name() Protocol {
	return WireGuard
}
func (WireGuardServer) isServerProtocol() {}
