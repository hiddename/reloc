// Command relocd serves the reloc API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/uhiddename/reloc/internal/api"
	"github.com/uhiddename/reloc/internal/app"
	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/store"
)

const (
	defaultAddr = "127.0.0.1:8080"

	// how long a client may take to send headers; without this limit
	// a slow client holds its connection forever
	readHeaderTimeout = 5 * time.Second
	// how long-running requests get to finish on shutdown
	shutdownTimeout = 10 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "relocd:", err)
		// os.Exit skips deferred calls
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	token := os.Getenv("RELOCD_TOKEN")
	if token == "" {
		return errors.New("RELOCD_TOKEN is not set")
	}
	addr := os.Getenv("RELOCD_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()

	a, err := newApp(store.New(pool))
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(a, token),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// buffered: the goroutine must be able to exit if nobody reads the error
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		// could not start, for example the port is taken
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	// a new context: ctx is already canceled, and Shutdown would return at once
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newApp(st *store.Store) (*app.App, error) {
	path := os.Getenv("RELOCD_SSH_KEY")
	if path == "" {
		slog.Warn("RELOCD_SSH_KEY is not set, applying configs is disabled")
		return app.New(st), nil
	}
	auth, err := remote.KeyFileAuth(path)
	if err != nil {
		return nil, err
	}
	return app.New(st).WithAuth(auth), nil
}
