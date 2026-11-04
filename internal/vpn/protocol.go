package vpn

import (
	"errors"
	"fmt"
)

var ErrInvalidProtocol = errors.New("vpn: invalid protocol")
var ErrInvalidTransport = errors.New("vpn: invalid transport")

type (
	Protocol  string
	Transport string
)

const (
	WireGuard Protocol  = "wireguard"
	UDP       Transport = "udp"
	TCP       Transport = "tcp"
)

func ParseProtocol(s string) (Protocol, error) {
	switch p := Protocol(s); p {
	case WireGuard:
		return p, nil
	}
	var zero Protocol
	return zero, fmt.Errorf("%w: %q", ErrInvalidProtocol, s)
}

func ParseTransport(s string) (Transport, error) {
	switch t := Transport(s); t {
	case UDP, TCP:
		return t, nil
	}
	var zero Transport
	return zero, fmt.Errorf("%w: %q", ErrInvalidTransport, s)
}
