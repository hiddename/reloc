package wg

import (
	"net/netip"

	"github.com/uhiddename/reloc/internal/inet"
)

type Interface struct {
	PrivateKey PrivateKey
	ListenPort uint16
	Address    []netip.Prefix
	MTU        uint16
	DNS        []netip.Addr
	DNSSearch  []inet.DNSName
	PostUp     []string
	PostDown   []string
}
