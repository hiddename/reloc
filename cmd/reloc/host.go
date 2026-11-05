package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

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
