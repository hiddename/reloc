package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

const (
	insertHostSQL = `
insert into hosts (name) values (@name) returning id, created_at
`
	insertHostSSHSQL = `
insert into host_ssh (host_id, ssh_addr, ssh_name, port, username, host_key)
values (@host_id, @ssh_addr, @ssh_name, @port, @username, @host_key)
`
	selectHostSQL = `
select
	h.id, h.name, h.created_at,
	ssh.ssh_addr, ssh.ssh_name, ssh.port as ssh_port,
	ssh.username as ssh_username, ssh.host_key as ssh_host_key
from hosts h
join host_ssh ssh on ssh.host_id = h.id
`
)

func (s *Store) CreateHost(ctx context.Context, h vpn.Host) (vpn.Host, error) {
	h, err := s.createHost(ctx, h)
	if err != nil {
		return vpn.Host{}, fmt.Errorf("store: create host: %w", err)
	}
	return h, nil
}

func (s *Store) GetHostByName(ctx context.Context, name string) (vpn.Host, error) {
	h, err := s.getHostByName(ctx, name)
	if err != nil {
		return vpn.Host{}, fmt.Errorf("store: get host by name: %w", err)
	}
	return h, nil
}

func (s *Store) GetHost(ctx context.Context, id int64) (vpn.Host, error) {
	h, err := s.getHost(ctx, id)
	if err != nil {
		return vpn.Host{}, fmt.Errorf("store: get host: %w", err)
	}
	return h, nil
}

func (s *Store) createHost(ctx context.Context, h vpn.Host) (vpn.Host, error) {
	var zero vpn.Host
	if h.SSH.HostKey == nil {
		return zero, errors.New("ssh host key is not set")
	}
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, insertHostSQL, pgx.NamedArgs{"name": h.Name}).
			Scan(&h.ID, &h.CreatedAt)
		if err != nil {
			return err
		}
		args := pgx.NamedArgs{
			"host_id":  h.ID,
			"ssh_addr": nilIfZero(h.SSH.Addr.Addr()),
			"ssh_name": nilIfZero(h.SSH.Addr.Name()),
			"port":     h.SSH.Addr.Port(),
			"username": h.SSH.User,
			"host_key": h.SSH.HostKey.Marshal(),
		}
		if _, err := tx.Exec(ctx, insertHostSSHSQL, args); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	return h, nil
}

type hostRow struct {
	ID          int64       `db:"id"`
	Name        string      `db:"name"`
	CreatedAt   time.Time   `db:"created_at"`
	SSHAddr     *netip.Addr `db:"ssh_addr"`
	SSHName     *string     `db:"ssh_name"`
	SSHPort     int32       `db:"ssh_port"`
	SSHUsername string      `db:"ssh_username"`
	SSHHostKey  []byte      `db:"ssh_host_key"`
}

func (r hostRow) host() (vpn.Host, error) {
	var zero vpn.Host
	endpoint, err := endpointFromTuple(r.SSHAddr, r.SSHName, r.SSHPort)
	if err != nil {
		return zero, err
	}
	hostKey, err := ssh.ParsePublicKey(r.SSHHostKey)
	if err != nil {
		return zero, err
	}
	return vpn.Host{
		ID:   r.ID,
		Name: r.Name,
		SSH: vpn.SSH{
			Addr:    endpoint,
			User:    r.SSHUsername,
			HostKey: hostKey,
		},
		CreatedAt: r.CreatedAt,
	}, nil
}

func (s *Store) getHostByName(ctx context.Context, name string) (vpn.Host, error) {
	var zero vpn.Host
	rows, err := s.db.Query(ctx,
		selectHostSQL+"where h.name = @name",
		pgx.NamedArgs{"name": name},
	)
	if err != nil {
		return zero, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[hostRow])
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return zero, fmt.Errorf("%w: host %q", ErrNotFound, name)
	case err != nil:
		return zero, err
	}
	return row.host()
}

func (s *Store) getHost(ctx context.Context, id int64) (vpn.Host, error) {
	var zero vpn.Host
	rows, err := s.db.Query(ctx,
		selectHostSQL+"where h.id = @id",
		pgx.NamedArgs{"id": id},
	)
	if err != nil {
		return zero, err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[hostRow])
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return zero, fmt.Errorf("%w: host %d", ErrNotFound, id)
	case err != nil:
		return zero, err
	}
	return row.host()
}
