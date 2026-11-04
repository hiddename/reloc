package inet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

var ErrInvalidEndpoint = errors.New("inet: invalid endpoint")

type Endpoint struct {
	addr netip.Addr
	name DNSName
	port uint16
}

func (e Endpoint) Addr() netip.Addr {
	return e.addr
}

func (e Endpoint) Name() DNSName {
	return e.name
}

func (e Endpoint) Port() uint16 {
	return e.port
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

func EndpointFromHost(host string, port uint16) (Endpoint, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return EndpointFromAddr(a, port)
	}
	n, err := ParseDNSName(host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("inet: endpoint host %q: not an IP address or DNS name", host)
	}
	return EndpointFromName(n, port)
}

func ParseEndpoint(s string) (Endpoint, error) {
	hostStr, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Endpoint{}, fmt.Errorf("inet: parse endpoint %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Endpoint{}, fmt.Errorf("inet: parse endpoint %q: invalid port", s)
	}
	return EndpointFromHost(hostStr, uint16(port))
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
