package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"text/tabwriter"

	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/wg"
)

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

func addrOrDash(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	return a.String()
}
