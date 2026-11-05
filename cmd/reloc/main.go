package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/migrations"
)

type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

var errUsage = usageError{errors.New("usage requested")}
var errShown = errors.New("error already shown")

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, flag.ErrHelp):
			os.Exit(0)
		case errors.Is(err, errShown):
			os.Exit(2)
		}
		if errors.Is(err, errUsage) {
			_, _ = fmt.Fprintf(os.Stderr, "reloc %s\n\n%s\n", version(), usageText())
		} else {
			_, _ = fmt.Fprintln(os.Stderr, "reloc:", err)
		}
		if _, ok := errors.AsType[usageError](err); ok {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	cmd, rest, ok := findCommand(args)
	if !ok {
		return usagef(
			"unknown command %q, run \"reloc\" for the list",
			strings.Join(args[:min(2, len(args))], " "),
		)
	}
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()
	return cmd.run(ctx, env{app: app.New(store.New(pool)), pool: pool}, rest)
}

func migrate(ctx context.Context, e env, args []string) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	dir, err := fs.Sub(migrations.Postgres, "postgres")
	if err != nil {
		return err
	}
	return store.Migrate(ctx, e.pool, dir)
}
