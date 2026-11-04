package app

import (
	"fmt"
	"net/netip"

	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

func ServerConfig(serv vpn.Server, clients []vpn.Client) (wg.Config, error) {
	conf, err := serverConfig(serv, clients)
	if err != nil {
		return wg.Config{}, fmt.Errorf("app: server config: %w", err)
	}
	return conf, nil
}

func ClientConfig(serv vpn.Server, c vpn.Client) (wg.Config, error) {
	conf, err := clientConfig(serv, c)
	if err != nil {
		return wg.Config{}, fmt.Errorf("app: client config: %w", err)
	}
	return conf, nil
}

func serverConfig(serv vpn.Server, clients []vpn.Client) (wg.Config, error) {
	var zero wg.Config
	sp, err := serv.WireGuard()
	if err != nil {
		return zero, err
	}
	peers := make([]wg.Peer, 0, len(clients))
	for _, c := range clients {
		if err := checkServerClient(serv, c); err != nil {
			return zero, err
		}
		if !c.Enabled {
			continue
		}
		peer, err := serverPeer(c)
		if err != nil {
			return zero, err
		}
		peers = append(peers, peer)
	}
	postUp, postDown := serverHooks(serv)
	return wg.Config{
		Interface: wg.Interface{
			PrivateKey: sp.PrivateKey,
			ListenPort: serv.ListenPort,
			Address:    serverAddrs(serv),
			MTU:        sp.MTU,
			PostUp:     postUp,
			PostDown:   postDown,
		},
		Peers: peers,
	}, nil
}

func clientConfig(serv vpn.Server, c vpn.Client) (wg.Config, error) {
	var zero wg.Config
	if err := checkServerClient(serv, c); err != nil {
		return zero, err
	}
	sp, err := serv.WireGuard()
	if err != nil {
		return zero, err
	}
	cp, err := c.WireGuard()
	if err != nil {
		return zero, err
	}
	return wg.Config{
		Interface: wg.Interface{
			PrivateKey: cp.PrivateKey,
			Address:    clientAddrs(serv, c),
			MTU:        sp.ClientMTU,
			DNS:        serv.ClientDNS,
			DNSSearch:  serv.ClientDNSSearch,
		},
		Peers: []wg.Peer{
			{
				PublicKey:           sp.PrivateKey.PublicKey(),
				PresharedKey:        cp.PresharedKey,
				AllowedIPs:          c.TunnelNetworks,
				Endpoint:            serv.Endpoint,
				PersistentKeepalive: cp.PersistentKeepalive,
			},
		},
	}, nil
}

func serverPeer(c vpn.Client) (wg.Peer, error) {
	cp, err := c.WireGuard()
	if err != nil {
		return wg.Peer{}, err
	}
	return wg.Peer{
		PublicKey:    cp.PrivateKey.PublicKey(),
		PresharedKey: cp.PresharedKey,
		AllowedIPs:   clientAllowedIPs(c),
	}, nil
}

func serverAddrs(serv vpn.Server) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range []*vpn.Network{serv.IPv4, serv.IPv6} {
		if n != nil {
			out = append(out, netip.PrefixFrom(n.Addr, n.Prefix.Bits()))
		}
	}
	return out
}

func clientAllowedIPs(c vpn.Client) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range []netip.Addr{c.IPv4, c.IPv6} {
		if a.IsValid() {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func clientAddrs(serv vpn.Server, c vpn.Client) []netip.Prefix {
	var out []netip.Prefix
	if serv.IPv4 != nil && c.IPv4.IsValid() {
		out = append(out, netip.PrefixFrom(c.IPv4, serv.IPv4.Prefix.Bits()))
	}
	if serv.IPv6 != nil && c.IPv6.IsValid() {
		out = append(out, netip.PrefixFrom(c.IPv6, serv.IPv6.Prefix.Bits()))
	}
	return out
}

func checkServerClient(serv vpn.Server, c vpn.Client) error {
	if c.ServerID != serv.ID {
		return fmt.Errorf(
			"client %d (%s) belongs to server %d, not %d",
			c.ID, c.Name, c.ServerID, serv.ID,
		)
	}
	return nil
}
