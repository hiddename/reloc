package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/app"
)

type env struct {
	app  *app.App
	pool *pgxpool.Pool
}

type command struct {
	name  string
	flags string
	run   func(ctx context.Context, e env, args []string) error
}

var commands = []command{
	{"migrate", "", migrate},
	{"host add", "-name -ssh -host-key", hostAdd},
	{"host check", "-name", hostCheck},
	{"server add", "-host -endpoint -ipv4 [-ipv6 -port -iface -egress -dns -dns-search]", serverAdd},
	{"server conf", "-server-id", serverConf},
	{"server apply", "-server-id", serverApply},
	{"client list", "-server-id", clientList},
	{"client add", "-server-id -name [-split -apply]", clientAdd},
	{"client remove", "-server-id -name [-apply]", clientRemove},
	{"client disable", "-server-id -name [-apply]", clientDisable},
	{"client enable", "-server-id -name [-apply]", clientEnable},
	{"client conf", "-server-id -name", clientConf},
}

func findCommand(args []string) (command, []string, bool) {
	for _, c := range commands {
		words := strings.Fields(c.name)
		if len(args) >= len(words) && slices.Equal(args[:len(words)], words) {
			return c, args[len(words):], true
		}
	}
	return command{}, nil, false
}

func usageText() string {
	var b strings.Builder
	b.WriteString("Usage:\n")
	for _, c := range commands {
		line := fmt.Sprintf("  reloc %-14s %s", c.name, c.flags)
		b.WriteString(strings.TrimRight(line, " ") + "\n")
	}
	b.WriteString("\nRun \"reloc <command> -h\" for flags.")
	return b.String()
}
