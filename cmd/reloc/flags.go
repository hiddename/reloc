package main

import (
	"errors"
	"flag"
	"strings"
)

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errShown
	}
	if fs.NArg() > 0 {
		return usagef("%s: unexpected argument %q", fs.Name(), fs.Arg(0))
	}
	return nil
}

func parseList[T any](s string, parse func(string) (T, error)) ([]T, error) {
	if s == "" {
		return nil, nil
	}
	var out []T
	for e := range strings.SplitSeq(s, ",") {
		v, err := parse(strings.TrimSpace(e))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func serverIDFlag(flags *flag.FlagSet) *int64 {
	return flags.Int64("server-id", 0, "server ID, see server add")
}

func requireServerID(flags *flag.FlagSet, serverID int64) error {
	if serverID <= 0 {
		flags.Usage()
		return usagef("%s: -server-id (positive) is required", flags.Name())
	}
	return nil
}

func clientFlags(flags *flag.FlagSet) (serverID *int64, name *string) {
	return serverIDFlag(flags), flags.String("name", "", "client name, unique on the server")
}

func requireClient(flags *flag.FlagSet, serverID int64, name string) error {
	if serverID <= 0 || name == "" {
		flags.Usage()
		return usagef("%s: -server-id (positive) and -name are required", flags.Name())
	}
	return nil
}
