package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

const (
	insertVPNClientsSQL = `
insert into vpn_clients (server_id, protocol, name, ipv4_address, ipv6_address, tunnel_networks, enabled)
values (@server_id, @protocol, @name, @ipv4_address, @ipv6_address, @tunnel_networks, @enabled)
returning id, created_at
`
	insertWGClientsSQL = `
insert into wg_clients (client_id, server_id, private_key, public_key, preshared_key, persistent_keepalive)
values (@client_id, @server_id, @private_key, @public_key, @preshared_key, @persistent_keepalive)
`
	deleteVPNClientsSQL = `
delete from vpn_clients
where id = @id
`
	updateVPNClientsEnabledSQL = `
update vpn_clients
set enabled = @enabled
where id = @id
`
	selectVPNClientsSQL = `
select
	c.id, c.server_id, c.protocol, c.name, c.ipv4_address, c.ipv6_address,
	c.tunnel_networks, c.enabled, c.created_at,
	wgc.private_key as wgc_private_key,
	wgc.preshared_key as wgc_preshared_key,
	wgc.persistent_keepalive as wgc_persistent_keepalive
from vpn_clients c
join wg_clients wgc on wgc.client_id = c.id
`
)

var (
	ErrClientNameTaken    = errors.New("client name is already taken")
	ErrClientAddressTaken = errors.New("client address is already taken")
)

func (s *Store) CreateClient(ctx context.Context, c vpn.Client) (vpn.Client, error) {
	c, err := s.createClient(ctx, c)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("store: create client: %w", err)
	}
	return c, nil
}

func (s *Store) ListClients(ctx context.Context, serverID int64) ([]vpn.Client, error) {
	clients, err := s.listClients(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("store: list clients: %w", err)
	}
	return clients, nil
}

func (s *Store) DeleteClient(ctx context.Context, clientID int64) error {
	err := s.deleteClient(ctx, clientID)
	if err != nil {
		return fmt.Errorf("store: delete client: %w", err)
	}
	return nil
}

func (s *Store) SetClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	err := s.setClientEnabled(ctx, clientID, enabled)
	if err != nil {
		return fmt.Errorf("store: set client enabled: %w", err)
	}
	return nil
}

func (s *Store) GetClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	c, err := s.getClientByName(ctx, serverID, name)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("store: get client by name: %w", err)
	}
	return c, nil
}

func (s *Store) GetClient(ctx context.Context, id int64) (vpn.Client, error) {
	c, err := s.getClient(ctx, id)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("store: get client by id: %w", err)
	}
	return c, nil
}

func (s *Store) createClient(ctx context.Context, c vpn.Client) (vpn.Client, error) {
	var zero vpn.Client
	if c.Protocol == nil {
		return zero, errors.New("protocol is not set")
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		args := pgx.NamedArgs{
			"server_id":       c.ServerID,
			"protocol":        c.Protocol.Name(),
			"name":            c.Name,
			"ipv4_address":    nilIfZero(c.IPv4),
			"ipv6_address":    nilIfZero(c.IPv6),
			"tunnel_networks": c.TunnelNetworks,
			"enabled":         c.Enabled,
		}
		if err := tx.QueryRow(
			ctx,
			insertVPNClientsSQL,
			args,
		).Scan(&c.ID, &c.CreatedAt); err != nil {
			return clientConflict(err)
		}
		switch p := c.Protocol.(type) {
		case vpn.WireGuardClient:
			args = pgx.NamedArgs{
				"client_id":            c.ID,
				"server_id":            c.ServerID,
				"private_key":          p.PrivateKey.Bytes(),
				"public_key":           p.PrivateKey.PublicKey().Bytes(),
				"preshared_key":        p.PresharedKey.Bytes(),
				"persistent_keepalive": nilIfZero(p.PersistentKeepalive),
			}
			if _, err := tx.Exec(
				ctx,
				insertWGClientsSQL,
				args,
			); err != nil {
				return err
			}
		case nil:
			return fmt.Errorf("%w: %T", ErrUnsupportedProtocol, c.Protocol)
		default:
			return fmt.Errorf("%w: %v", ErrUnsupportedProtocol, c.Protocol.Name())
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	return c, nil
}

func clientConflict(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgErrCodeUniqueViolation {
		return err
	}
	switch pgErr.ConstraintName {
	case "vpn_clients_server_id_name_key":
		return fmt.Errorf("%w: %s", ErrClientNameTaken, pgErr.ConstraintName)
	case "vpn_clients_server_id_ipv4_address_key", "vpn_clients_server_id_ipv6_address_key":
		return fmt.Errorf("%w: %s", ErrClientAddressTaken, pgErr.ConstraintName)
	}
	return err
}

type clientRow struct {
	ID                                 int64          `db:"id"`
	ServerID                           int64          `db:"server_id"`
	Protocol                           string         `db:"protocol"`
	Name                               string         `db:"name"`
	IPv4Address                        *netip.Addr    `db:"ipv4_address"`
	IPv6Address                        *netip.Addr    `db:"ipv6_address"`
	TunnelNetworks                     []netip.Prefix `db:"tunnel_networks"`
	Enabled                            bool           `db:"enabled"`
	CreatedAt                          time.Time      `db:"created_at"`
	WireGuardClientPrivateKey          []byte         `db:"wgc_private_key"`
	WireGuardClientPresharedKey        []byte         `db:"wgc_preshared_key"`
	WireGuardClientPersistentKeepalive *int32         `db:"wgc_persistent_keepalive"`
}

func (r clientRow) wireGuard() (vpn.WireGuardClient, error) {
	pk, err := wg.KeyFromBytes[wg.PrivateKey](r.WireGuardClientPrivateKey)
	if err != nil {
		return vpn.WireGuardClient{}, err
	}
	psk, err := wg.KeyFromBytes[wg.PresharedKey](r.WireGuardClientPresharedKey)
	if err != nil {
		return vpn.WireGuardClient{}, err
	}
	return vpn.WireGuardClient{
		PrivateKey:          pk,
		PresharedKey:        psk,
		PersistentKeepalive: uint16(zeroIfNil(r.WireGuardClientPersistentKeepalive)),
	}, nil
}

func (r clientRow) client() (vpn.Client, error) {
	var zero vpn.Client
	protocolName, err := vpn.ParseProtocol(r.Protocol)
	if err != nil {
		return zero, err
	}
	var protocol vpn.ClientProtocol
	switch protocolName {
	case vpn.WireGuard:
		if protocol, err = r.wireGuard(); err != nil {
			return zero, err
		}
	default:
		return zero, fmt.Errorf("%w: %v", ErrUnsupportedProtocol, protocolName)
	}

	return vpn.Client{
		ID:             r.ID,
		ServerID:       r.ServerID,
		Name:           r.Name,
		IPv4:           zeroIfNil(r.IPv4Address),
		IPv6:           zeroIfNil(r.IPv6Address),
		TunnelNetworks: r.TunnelNetworks,
		Enabled:        r.Enabled,
		Protocol:       protocol,
		CreatedAt:      r.CreatedAt,
	}, nil
}

func (s *Store) listClients(ctx context.Context, serverID int64) ([]vpn.Client, error) {
	pgRows, err := s.db.Query(ctx,
		selectVPNClientsSQL+"where c.server_id = @server_id order by c.id",
		pgx.NamedArgs{
			"server_id": serverID,
		},
	)
	if err != nil {
		return nil, err
	}
	rows, err := pgx.CollectRows(pgRows, pgx.RowToStructByName[clientRow])
	if err != nil {
		return nil, err
	}
	return mapSliceErr(rows, clientRow.client)
}

func (s *Store) deleteClient(ctx context.Context, clientID int64) error {
	tag, err := s.db.Exec(ctx, deleteVPNClientsSQL, pgx.NamedArgs{
		"id": clientID,
	})
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: client %d", ErrNotFound, clientID)
	}
	return nil
}

func (s *Store) setClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	tag, err := s.db.Exec(ctx, updateVPNClientsEnabledSQL, pgx.NamedArgs{
		"id":      clientID,
		"enabled": enabled,
	})
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: client %d", ErrNotFound, clientID)
	}
	return nil
}

func (s *Store) getClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	c, err := s.fetchClient(ctx,
		selectVPNClientsSQL+"where c.server_id = @server_id and c.name = @name",
		pgx.NamedArgs{
			"server_id": serverID,
			"name":      name,
		},
	)
	switch {
	case errors.Is(err, ErrNotFound):
		return vpn.Client{}, fmt.Errorf("%w: client %q on server %d", err, name, serverID)
	case err != nil:
		return vpn.Client{}, err
	}
	return c, nil
}

func (s *Store) getClient(ctx context.Context, id int64) (vpn.Client, error) {
	c, err := s.fetchClient(ctx,
		selectVPNClientsSQL+"where c.id = @id",
		pgx.NamedArgs{
			"id": id,
		},
	)
	switch {
	case errors.Is(err, ErrNotFound):
		return vpn.Client{}, fmt.Errorf("%w: client %d", err, id)
	case err != nil:
		return vpn.Client{}, err
	}
	return c, nil
}

func (s *Store) fetchClient(ctx context.Context, sql string, args pgx.NamedArgs) (vpn.Client, error) {
	pgRows, err := s.db.Query(ctx, sql, args)
	if err != nil {
		return vpn.Client{}, err
	}
	row, err := pgx.CollectExactlyOneRow(pgRows, pgx.RowToStructByName[clientRow])
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return vpn.Client{}, ErrNotFound
	case err != nil:
		return vpn.Client{}, err
	}
	c, err := row.client()
	if err != nil {
		return vpn.Client{}, err
	}
	return c, nil
}
