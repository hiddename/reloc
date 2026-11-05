package vpn

import (
	"fmt"
	"net/netip"
	"regexp"
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

// ValidationError is an invalid value from the user. Its message is safe
// to show: it holds no internal details.
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string { return e.Msg }

var clientNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

// ValidateClientName checks a client name. Keep in sync with the iface_name
// domain in the database.
func ValidateClientName(name string) error {
	if !clientNameRe.MatchString(name) {
		return &ValidationError{Msg: fmt.Sprintf(
			"client name %q: want 1-15 letters, digits, _ or -", name,
		)}
	}
	return nil
}

// ValidateTunnelNetworks checks the networks routed through a client tunnel.
func ValidateTunnelNetworks(tunnel []netip.Prefix) error {
	for _, p := range tunnel {
		if !p.IsValid() {
			return &ValidationError{Msg: "tunnel network is not valid"}
		}
		if p != p.Masked() {
			return &ValidationError{Msg: fmt.Sprintf(
				"tunnel network %v has host bits set, want %v", p, p.Masked(),
			)}
		}
	}
	return nil
}
