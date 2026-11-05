package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

const createClientAttempts = 10

func (a *App) ListClients(ctx context.Context, serverID int64) ([]vpn.Client, error) {
	if _, err := a.store.GetServer(ctx, serverID); err != nil {
		return nil, fmt.Errorf("app: list clients: %w", err)
	}
	clients, err := a.store.ListClients(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("app: list clients: %w", err)
	}
	return clients, nil
}

func (a *App) GetClient(ctx context.Context, id int64) (vpn.Client, error) {
	c, err := a.getClient(ctx, id)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: get client: %w", err)
	}
	return c, nil
}

func (a *App) GetClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	c, err := a.getClientByName(ctx, serverID, name)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: get client by name: %w", err)
	}
	return c, nil
}

func (a *App) CreateClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	c, err := a.createClient(ctx, serverID, name, tunnel)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: create client: %w", err)
	}
	return c, nil
}

func (a *App) DeleteClient(ctx context.Context, clientID int64) error {
	if err := a.deleteClient(ctx, clientID); err != nil {
		return fmt.Errorf("app: delete client: %w", err)
	}
	return nil
}

func (a *App) SetClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	if err := a.setClientEnabled(ctx, clientID, enabled); err != nil {
		return fmt.Errorf("app: set client enabled: %w", err)
	}
	return nil
}

func (a *App) ClientConf(ctx context.Context, id int64) (wg.Config, error) {
	conf, err := a.clientConf(ctx, id)
	if err != nil {
		return wg.Config{}, fmt.Errorf("app: client conf: %w", err)
	}
	return conf, nil
}

func (a *App) getClient(ctx context.Context, id int64) (vpn.Client, error) {
	return a.store.GetClient(ctx, id)
}

func (a *App) getClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	return a.store.GetClientByName(ctx, serverID, name)
}

func (a *App) createClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	if err := vpn.ValidateClientName(name); err != nil {
		return vpn.Client{}, err
	}
	if err := vpn.ValidateTunnelNetworks(tunnel); err != nil {
		return vpn.Client{}, err
	}
	var (
		c   vpn.Client
		err error
	)
	for range createClientAttempts {
		c, err = a.tryCreateClient(ctx, serverID, name, tunnel)
		if !errors.Is(err, store.ErrClientAddressTaken) {
			return c, err
		}
	}
	return vpn.Client{}, fmt.Errorf(
		"address conflict persisted after %d attempts, try again: %w",
		createClientAttempts, err,
	)
}

func (a *App) tryCreateClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	var zero vpn.Client
	serv, err := a.store.GetServer(ctx, serverID)
	if err != nil {
		return zero, err
	}
	if _, err = serv.WireGuard(); err != nil {
		return zero, err
	}
	clients, err := a.store.ListClients(ctx, serverID)
	if err != nil {
		return zero, err
	}
	ipv4, err := allocAddr(
		serv.IPv4, clients,
		func(c vpn.Client) netip.Addr { return c.IPv4 },
	)
	if err != nil {
		return zero, err
	}
	ipv6, err := allocAddr(
		serv.IPv6, clients,
		func(c vpn.Client) netip.Addr { return c.IPv6 },
	)
	if err != nil {
		return zero, err
	}
	if len(tunnel) == 0 {
		tunnel = wg.DefaultAllowedIPs()
	}
	newClient := vpn.Client{
		ServerID:       serverID,
		Name:           name,
		IPv4:           ipv4,
		IPv6:           ipv6,
		TunnelNetworks: tunnel,
		Enabled:        true,
		Protocol: vpn.WireGuardClient{
			PrivateKey:          wg.Genkey(),
			PresharedKey:        wg.Genpsk(),
			PersistentKeepalive: wg.DefaultPersistentKeepalive,
		},
	}
	return a.store.CreateClient(ctx, newClient)
}

func (a *App) deleteClient(ctx context.Context, clientID int64) error {
	return a.store.DeleteClient(ctx, clientID)
}

func (a *App) setClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	return a.store.SetClientEnabled(ctx, clientID, enabled)
}

func (a *App) clientConf(ctx context.Context, id int64) (wg.Config, error) {
	var zero wg.Config
	client, err := a.getClient(ctx, id)
	if err != nil {
		return zero, err
	}
	serv, err := a.getServer(ctx, client.ServerID)
	if err != nil {
		return zero, err
	}
	conf, err := ClientConfig(serv, client)
	if err != nil {
		return zero, err
	}
	return conf, nil
}
