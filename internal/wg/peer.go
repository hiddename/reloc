package wg

import (
	"net/netip"
)

const (
	DefaultPersistentKeepalive = 25
)

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

type Peer struct {
	PublicKey           PublicKey
	PresharedKey        PresharedKey
	AllowedIPs          []netip.Prefix
	Endpoint            Endpoint
	PersistentKeepalive uint16
}

func DefaultAllowedIPs() []netip.Prefix {
	return []netip.Prefix{allIPv4, allIPv6}
}
