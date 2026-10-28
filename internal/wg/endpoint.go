package wg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

var ErrInvalidEndpoint = errors.New("wg: invalid endpoint")

type Endpoint struct {
	addr netip.Addr
	name DNSName
	port uint16
}

func validateEndpointPort(port uint16) error {
	if port == 0 {
		return fmt.Errorf("%w: port must not be zero", ErrInvalidEndpoint)
	}
	return nil
}

func EndpointFromAddr(a netip.Addr, port uint16) (Endpoint, error) {
	var zero Endpoint
	if err := validateEndpointPort(port); err != nil {
		return zero, err
	}
	if !a.IsValid() {
		return zero, fmt.Errorf("%w: addr is not set", ErrInvalidEndpoint)
	}
	a = a.Unmap()
	if a.Zone() != "" {
		return zero, fmt.Errorf("%w: addr must not have a zone", ErrInvalidEndpoint)
	}
	return Endpoint{
		addr: a,
		port: port,
	}, nil
}

func MustEndpointFromAddr(a netip.Addr, port uint16) Endpoint {
	e, err := EndpointFromAddr(a, port)
	if err != nil {
		panic(err)
	}
	return e
}

func EndpointFromName(n DNSName, port uint16) (Endpoint, error) {
	var zero Endpoint
	if err := validateEndpointPort(port); err != nil {
		return zero, err
	}
	if n == (DNSName{}) {
		return zero, fmt.Errorf("%w: name is not set", ErrInvalidEndpoint)
	}
	return Endpoint{
		name: n,
		port: port,
	}, nil
}

func (e Endpoint) host() string {
	if e.addr.IsValid() {
		return e.addr.String()
	}
	return e.name.String()
}

func (e Endpoint) String() string {
	return net.JoinHostPort(
		e.host(),
		strconv.FormatUint(uint64(e.port), 10),
	)
}

func (e Endpoint) IsZero() bool {
	var zero Endpoint
	return e == zero
}
