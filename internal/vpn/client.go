package vpn

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/uhiddename/reloc/internal/wg"
)

type ClientProtocol interface {
	Name() Protocol
	isClientProtocol()
}

type Client struct {
	ID             int64
	ServerID       int64
	Name           string
	IPv4           netip.Addr
	IPv6           netip.Addr
	TunnelNetworks []netip.Prefix
	Enabled        bool
	Protocol       ClientProtocol
	CreatedAt      time.Time
}

func (c Client) WireGuard() (WireGuardClient, error) {
	cp, ok := c.Protocol.(WireGuardClient)
	if !ok {
		return WireGuardClient{}, fmt.Errorf(
			"vpn: client %d (%s): protocol is %T, want wireguard",
			c.ID, c.Name, c.Protocol,
		)
	}
	return cp, nil
}

type WireGuardClient struct {
	PrivateKey          wg.PrivateKey
	PresharedKey        wg.PresharedKey
	PersistentKeepalive uint16
}

var _ ClientProtocol = WireGuardClient{}

func (WireGuardClient) Name() Protocol {
	return WireGuard
}

func (WireGuardClient) isClientProtocol() {}
