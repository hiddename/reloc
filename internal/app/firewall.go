package app

import (
	"fmt"
	"strings"

	"github.com/uhiddename/reloc/internal/vpn"
)

func serverHooks(serv vpn.Server) (up, down []string) {
	if serv.IPv4 != nil {
		up = append(up, "sysctl -w net.ipv4.ip_forward=1")
	}
	if serv.IPv6 != nil {
		up = append(up, "sysctl -w net.ipv6.conf.all.forwarding=1")
	}
	up = append(up, "nft '"+nftRuleset(serv)+"'")
	down = append(down, "nft delete table inet "+nftTable(serv.InterfaceName))
	return up, down
}

func nftTable(iface string) string {
	return "reloc_" + iface
}

func nftBlock(name string, stmts []string) string {
	return name + " { " + strings.Join(stmts, "; ") + "; }"
}

func nftRuleset(serv vpn.Server) string {
	var (
		out   = fmt.Sprintf("%q", serv.EgressInterface)
		iface = serv.InterfaceName
	)
	if serv.EgressInterface == "" {
		out = fmt.Sprintf("!= %q", iface)
	}
	table := nftTable(iface)
	verdict := "accept"
	if serv.ClientIsolation {
		verdict = "drop"
	}
	postrouting := []string{
		"type nat hook postrouting priority srcnat",
		"policy accept",
	}
	if n := serv.IPv4; n != nil && n.NAT {
		postrouting = append(postrouting, fmt.Sprintf(
			"ip saddr %v oifname %s masquerade",
			n.Prefix, out,
		))
	}
	if n := serv.IPv6; n != nil && n.NAT {
		postrouting = append(postrouting, fmt.Sprintf(
			"ip6 saddr %v oifname %s masquerade",
			n.Prefix, out,
		))
	}
	return strings.Join([]string{
		"add table inet " + table,
		"delete table inet " + table,
		nftBlock("table inet "+table, []string{
			nftBlock("chain forward", []string{
				"type filter hook forward priority filter",
				"policy accept",
				fmt.Sprintf(
					"iifname %q oifname %q %s",
					iface, iface, verdict,
				),
				fmt.Sprintf(
					"iifname %q oifname %s accept",
					iface, out,
				),
				fmt.Sprintf(
					"iifname %s oifname %q ct state established,related accept",
					out, iface,
				),
				fmt.Sprintf(
					"iifname %s oifname %q drop",
					out, iface,
				),
			}),
			nftBlock("chain postrouting", postrouting),
		}),
	}, "; ")
}
