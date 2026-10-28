package wg

import (
	"net/netip"
)

type Interface struct {
	PrivateKey PrivateKey
	ListenPort uint16
	Address    []netip.Prefix
	MTU        uint16
	DNS        []netip.Addr
	DNSSearch  []DNSName
	PostUp     []string
	PostDown   []string
}
