package store

import (
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
)

var (
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	ErrNotFound            = errors.New("not found")
)

const pgErrCodeUniqueViolation = "23505"

type Store struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func nilIfZero[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

func nilIf[T any](v T, c bool) any {
	if c {
		return nil
	}
	return v
}

func zeroIfNil[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

func emptyIfNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func mapSlice[F, T any](s []F, fn func(F) T) []T {
	s2, _ := mapSliceErr(s, func(v F) (T, error) { return fn(v), nil })
	return s2
}

func mapSliceErr[F, T any](s []F, fn func(F) (T, error)) ([]T, error) {
	if s == nil {
		return nil, nil
	}
	s2 := make([]T, len(s))
	for i, v := range s {
		e, err := fn(v)
		if err != nil {
			return nil, err
		}
		s2[i] = e
	}
	return s2, nil
}

func endpointFromTuple(addr *netip.Addr, name *string, port int32) (inet.Endpoint, error) {
	switch {
	case addr != nil:
		return inet.EndpointFromAddr(*addr, uint16(port))
	case name != nil:
		n, err := inet.ParseDNSName(*name)
		if err != nil {
			return inet.Endpoint{}, err
		}
		return inet.EndpointFromName(n, uint16(port))
	default:
		return inet.Endpoint{}, errors.New("broken endpoint")
	}
}

func networkFromTuple(prefix *netip.Prefix, addr *netip.Addr, nat bool) *vpn.Network {
	if prefix == nil || addr == nil {
		return nil
	}
	return &vpn.Network{
		Prefix: *prefix,
		Addr:   *addr,
		NAT:    nat,
	}
}

func networkToTuple(n *vpn.Network) (prefix, addr any, nat bool) {
	if n == nil {
		return nil, nil, false
	}
	return n.Prefix, n.Addr, n.NAT
}
