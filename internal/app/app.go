package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

var ErrNoAuth = errors.New("ssh key is not configured")

type App struct {
	store      *store.Store
	auth       ssh.AuthMethod
	applyLocks serverLocks
}

func New(s *store.Store) *App {
	return &App{store: s}
}

// WithAuth returns an App that connects to hosts using auth. The new App has
// its own apply locks, so call it once, not per request.
func (a *App) WithAuth(auth ssh.AuthMethod) *App {
	return &App{store: a.store, auth: auth}
}

func (a *App) GetHostByName(ctx context.Context, name string) (vpn.Host, error) {
	h, err := a.store.GetHostByName(ctx, name)
	if err != nil {
		return vpn.Host{}, fmt.Errorf("app: get host by name: %w", err)
	}
	return h, nil
}

func (a *App) CreateHost(ctx context.Context, h vpn.Host) (vpn.Host, error) {
	h, err := a.store.CreateHost(ctx, h)
	if err != nil {
		return vpn.Host{}, fmt.Errorf("app: create host: %w", err)
	}
	return h, nil
}
