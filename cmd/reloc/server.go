package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

func serverAdd(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("server add", flag.ContinueOnError)
	hostName := flags.String("host", "", "host name, see host add")
	endpointStr := flags.String("endpoint", "", "public address or DNS name clients connect to")
	ipv4Str := flags.String("ipv4", "", "server IPv4 address with network prefix, e.g. 10.66.66.1/24")
	ipv6Str := flags.String("ipv6", "", "server IPv6 address with network prefix, e.g. fd42::1/64")
	listenPort := flags.Uint("port", vpn.WireGuardDefaultListenPort, "UDP listen port")
	iface := flags.String("iface", "wg0", "WireGuard interface name")
	egress := flags.String("egress", "", "interface towards the internet for NAT, e.g. eth0 (default: autodetect later)")
	dnsStr := flags.String("dns", "1.1.1.1,1.0.0.1", "comma-separated DNS servers for clients")
	dnsSearchStr := flags.String("dns-search", "", "comma-separated DNS search domains for clients")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *hostName == "" || *endpointStr == "" || *ipv4Str == "" {
		flags.Usage()
		return usagef("server add: -host, -endpoint and -ipv4 are required")
	}
	if *listenPort == 0 || *listenPort > 65535 {
		return usagef("server add: -port %d: want 1-65535", *listenPort)
	}
	endpoint, err := inet.EndpointFromHost(*endpointStr, uint16(*listenPort))
	if err != nil {
		return usagef("server add: -endpoint: %w", err)
	}
	var ipv4, ipv6 *vpn.Network
	if ipv4, err = vpn.ParseNetwork(*ipv4Str); err != nil {
		return usagef("server add: -ipv4: %w", err)
	}
	if !ipv4.Addr.Is4() {
		return usagef("server add: -ipv4 %s: want IPv4", *ipv4Str)
	}
	ipv4.NAT = true
	if *ipv6Str != "" {
		if ipv6, err = vpn.ParseNetwork(*ipv6Str); err != nil {
			return usagef("server add: -ipv6: %w", err)
		}
		if !ipv6.Addr.Is6() {
			return usagef("server add: -ipv6 %s: want IPv6", *ipv6Str)
		}
		ipv6.NAT = true
	}
	dns, err := parseList(*dnsStr, netip.ParseAddr)
	if err != nil {
		return usagef("server add: -dns: %w", err)
	}
	dnsSearch, err := parseList(*dnsSearchStr, inet.ParseDNSName)
	if err != nil {
		return usagef("server add: -dns-search: %w", err)
	}
	host, err := e.app.GetHostByName(ctx, *hostName)
	if err != nil {
		return err
	}
	serv := vpn.Server{
		HostID:          host.ID,
		Transport:       vpn.UDP,
		InterfaceName:   *iface,
		ListenPort:      uint16(*listenPort),
		Endpoint:        endpoint,
		IPv4:            ipv4,
		IPv6:            ipv6,
		EgressInterface: *egress,
		ClientIsolation: true,
		ClientDNS:       dns,
		ClientDNSSearch: dnsSearch,
		Protocol: vpn.WireGuardServer{
			PrivateKey: wg.Genkey(),
			MTU:        vpn.WireGuardDefaultMTU,
			ClientMTU:  vpn.WireGuardDefaultClientMTU,
		},
	}
	serv, err = e.app.CreateServer(ctx, serv)
	if err != nil {
		return err
	}
	fmt.Printf("server %d\n", serv.ID)
	return nil
}

func serverConf(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("server conf", flag.ContinueOnError)
	serverID := serverIDFlag(flags)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireServerID(flags, *serverID); err != nil {
		return err
	}

	conf, err := e.app.ServerConf(ctx, *serverID)
	if err != nil {
		return err
	}
	return wg.Render(os.Stdout, conf)
}

func serverApply(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("server apply", flag.ContinueOnError)
	serverID := serverIDFlag(flags)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireServerID(flags, *serverID); err != nil {
		return err
	}

	return applyServer(ctx, e.app, *serverID)
}

func applyServer(ctx context.Context, a *app.App, serverID int64) error {
	auth, agentConn, err := remote.AgentAuth()
	if err != nil {
		return err
	}
	defer func() { _ = agentConn.Close() }()
	action, err := a.WithAuth(auth).ApplyServer(ctx, serverID)
	if err != nil {
		return err
	}
	fmt.Println("server", serverID, action)
	return nil
}
