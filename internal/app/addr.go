package app

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/uhiddename/reloc/internal/vpn"
)

var ErrNetworkFull = errors.New("network is full")

func allocAddr(
	n *vpn.Network,
	clients []vpn.Client,
	addr func(vpn.Client) netip.Addr,
) (netip.Addr, error) {
	if n == nil {
		return netip.Addr{}, nil
	}
	var taken []netip.Addr
	for _, c := range clients {
		if a := addr(c); a.IsValid() {
			taken = append(taken, a)
		}
	}
	return nextFreeAddr(*n, taken)
}

func nextFreeAddr(n vpn.Network, taken []netip.Addr) (netip.Addr, error) {
	skip := make(map[netip.Addr]struct{}, len(taken)+1)
	skip[n.Addr] = struct{}{}
	for _, a := range taken {
		skip[a] = struct{}{}
	}
	for a := n.Prefix.Masked().Addr().Next(); n.Prefix.Contains(a.Next()); a = a.Next() {
		if _, ok := skip[a]; ok {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("%w: %v", ErrNetworkFull, n.Prefix)
}
