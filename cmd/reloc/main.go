package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"text/tabwriter"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
	"github.com/uhiddename/reloc/migrations"

	"golang.org/x/crypto/ssh"
)

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

var errUsage = usageError{errors.New("usage requested")}
var errShown = errors.New("error already shown")

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}

func serverIDFlag(flags *flag.FlagSet) *int64 {
	return flags.Int64("server-id", 0, "server ID, see server add")
}

func clientFlags(flags *flag.FlagSet) (serverID *int64, name *string) {
	return serverIDFlag(flags), flags.String("name", "", "client name, unique on the server")
}

func requireServerID(flags *flag.FlagSet, serverID int64) error {
	if serverID <= 0 {
		flags.Usage()
		return usagef("%s: -server-id (positive) is required", flags.Name())
	}
	return nil
}

func requireClient(flags *flag.FlagSet, serverID int64, name string) error {
	if serverID <= 0 || name == "" {
		flags.Usage()
		return usagef("%s: -server-id (positive) and -name are required", flags.Name())
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, flag.ErrHelp):
			os.Exit(0)
		case errors.Is(err, errShown):
			os.Exit(2)
		}
		if errors.Is(err, errUsage) {
			_, _ = fmt.Fprintf(os.Stderr, "reloc %s\n\n%s\n", version(), usageText())
		} else {
			_, _ = fmt.Fprintln(os.Stderr, "reloc:", err)
		}
		if _, ok := errors.AsType[usageError](err); ok {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	cmd, rest, ok := findCommand(args)
	if !ok {
		return usagef(
			"unknown command %q, run \"reloc\" for the list",
			strings.Join(args[:min(2, len(args))], " "),
		)
	}
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	return cmd.run(ctx, env{app: app.New(store.New(pool)), pool: pool}, rest)
}

func migrate(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	dir, err := fs.Sub(migrations.Postgres, "postgres")
	if err != nil {
		return err
	}
	return store.Migrate(ctx, e.pool, dir)
}

func hostAdd(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("host add", flag.ContinueOnError)
	name := flags.String("name", "", "host name")
	sshAddr := flags.String("ssh", "", "user@host:port")
	hostKey := flags.String("host-key", "", "SSH public key, authorized_keys format")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *name == "" || *sshAddr == "" || *hostKey == "" {
		flags.Usage()
		return usagef("host add: -name, -ssh and -host-key are required")
	}
	user, addr, ok := strings.Cut(*sshAddr, "@")
	if !ok || user == "" {
		return usagef("host add: -ssh %q: want user@host:port", *sshAddr)
	}
	endpoint, err := inet.ParseEndpoint(addr)
	if err != nil {
		return usagef("host add: -ssh: %w", err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(*hostKey))
	if err != nil {
		return usagef("host add: -host-key: %w", err)
	}
	host := vpn.Host{
		Name: *name,
		SSH: vpn.SSH{
			Addr:    endpoint,
			User:    user,
			HostKey: k,
		},
	}
	host, err = e.app.CreateHost(ctx, host)
	if err != nil {
		return err
	}
	fmt.Printf("host %d %s\n", host.ID, host.Name)
	return nil
}

func hostCheck(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("host check", flag.ContinueOnError)
	hostName := flags.String("name", "", "host name, see host add")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if *hostName == "" {
		flags.Usage()
		return usagef("host check: -name is required")
	}

	h, err := e.app.GetHostByName(ctx, *hostName)
	if err != nil {
		return err
	}

	auth, agentConn, err := remote.AgentAuth()
	if err != nil {
		return err
	}
	c, err := remote.Dial(ctx, h.SSH, auth)
	_ = agentConn.Close()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	out, err := c.Run(ctx, "wg --version && nft --version", nil)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

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

func clientList(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("client list", flag.ContinueOnError)
	serverID := serverIDFlag(flags)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireServerID(flags, *serverID); err != nil {
		return err
	}

	clients, err := e.app.ListClients(ctx, *serverID)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tNAME\tIPV4\tIPV6\tENABLED")
	for _, c := range clients {
		_, _ = fmt.Fprintf(
			w, "%d\t%s\t%v\t%v\t%v\n",
			c.ID, c.Name, addrOrDash(c.IPv4), addrOrDash(c.IPv6), c.Enabled,
		)
	}
	return w.Flush()
}

func clientAdd(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("client add", flag.ContinueOnError)
	serverID, name := clientFlags(flags)
	split := flags.Bool("split", false, "route only VPN networks through the tunnel (default: all traffic)")
	apply := flags.Bool("apply", false, "apply the config on the server right away")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireClient(flags, *serverID, *name); err != nil {
		return err
	}

	var tunnel []netip.Prefix
	if *split {
		serv, err := e.app.GetServer(ctx, *serverID)
		if err != nil {
			return err
		}
		if serv.IPv4 != nil {
			tunnel = append(tunnel, serv.IPv4.Prefix)
		}
		if serv.IPv6 != nil {
			tunnel = append(tunnel, serv.IPv6.Prefix)
		}
	}
	c, err := e.app.CreateClient(ctx, *serverID, *name, tunnel)
	if err != nil {
		if errors.Is(err, store.ErrClientNameTaken) {
			return fmt.Errorf("client %q already exists on server %d", *name, *serverID)
		}
		return err
	}
	fmt.Printf("client %d %s %v %v\n", c.ID, c.Name, addrOrDash(c.IPv4), addrOrDash(c.IPv6))
	if !*apply {
		return nil
	}
	if err := applyServer(ctx, e.app, *serverID); err != nil {
		return fmt.Errorf("client %q is created, but not applied: %w", c.Name, err)
	}
	return nil
}

func clientRemove(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("client remove", flag.ContinueOnError)
	serverID, name := clientFlags(flags)
	apply := flags.Bool("apply", false, "apply the config on the server right away")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireClient(flags, *serverID, *name); err != nil {
		return err
	}

	client, err := e.app.GetClientByName(ctx, *serverID, *name)
	if err != nil {
		return err
	}
	if err := e.app.DeleteClient(ctx, client.ID); err != nil {
		return err
	}
	if !*apply {
		fmt.Printf("client %q is removed; run \"reloc server apply -server-id %d\" to revoke access\n", *name, *serverID)
		return nil
	}
	fmt.Printf("client %q is removed\n", *name)
	if err := applyServer(ctx, e.app, *serverID); err != nil {
		return fmt.Errorf("client %q is removed, but not applied: %w", *name, err)
	}
	return nil
}

func clientDisable(ctx context.Context, e env, args []string) error {
	return setClientEnabled(ctx, e, "client disable", args, false)
}

func clientEnable(ctx context.Context, e env, args []string) error {
	return setClientEnabled(ctx, e, "client enable", args, true)
}

func setClientEnabled(ctx context.Context, e env, cmd string, args []string, enabled bool) error {
	done, access := "disabled", "revoke"
	if enabled {
		done, access = "enabled", "restore"
	}
	flags := flag.NewFlagSet(cmd, flag.ContinueOnError)
	serverID, name := clientFlags(flags)
	apply := flags.Bool("apply", false, "apply the config on the server right away")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireClient(flags, *serverID, *name); err != nil {
		return err
	}

	client, err := e.app.GetClientByName(ctx, *serverID, *name)
	if err != nil {
		return err
	}
	if err := e.app.SetClientEnabled(ctx, client.ID, enabled); err != nil {
		return err
	}
	if !*apply {
		fmt.Printf("client %q is %s; run \"reloc server apply -server-id %d\" to %s access\n", *name, done, *serverID, access)
		return nil
	}
	fmt.Printf("client %q is %s\n", *name, done)
	if err := applyServer(ctx, e.app, *serverID); err != nil {
		return fmt.Errorf("client %q is %s, but not applied: %w", *name, done, err)
	}
	return nil
}

func clientConf(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("client conf", flag.ContinueOnError)
	serverID, name := clientFlags(flags)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := requireClient(flags, *serverID, *name); err != nil {
		return err
	}

	client, err := e.app.GetClientByName(ctx, *serverID, *name)
	if err != nil {
		return err
	}
	conf, err := e.app.ClientConf(ctx, client.ID)
	if err != nil {
		return err
	}
	return wg.Render(os.Stdout, conf)
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

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errShown
	}
	if fs.NArg() > 0 {
		return usagef("%s: unexpected argument %q", fs.Name(), fs.Arg(0))
	}
	return nil
}

func parseList[T any](s string, parse func(string) (T, error)) ([]T, error) {
	if s == "" {
		return nil, nil
	}
	var out []T
	for e := range strings.SplitSeq(s, ",") {
		v, err := parse(strings.TrimSpace(e))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func addrOrDash(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}
