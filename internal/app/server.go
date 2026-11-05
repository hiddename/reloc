package app

import (
	"context"
	"fmt"

	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

func (a *App) GetServer(ctx context.Context, id int64) (vpn.Server, error) {
	c, err := a.getServer(ctx, id)
	if err != nil {
		return vpn.Server{}, fmt.Errorf("app: get server: %w", err)
	}
	return c, nil
}

func (a *App) CreateServer(ctx context.Context, serv vpn.Server) (vpn.Server, error) {
	serv, err := a.store.CreateServer(ctx, serv)
	if err != nil {
		return vpn.Server{}, fmt.Errorf("app: create server: %w", err)
	}
	return serv, nil
}

func (a *App) ServerConf(ctx context.Context, id int64) (wg.Config, error) {
	conf, err := a.serverConf(ctx, id)
	if err != nil {
		return wg.Config{}, fmt.Errorf("app: server conf: %w", err)
	}
	return conf, nil
}

func (a *App) getServer(ctx context.Context, id int64) (vpn.Server, error) {
	return a.store.GetServer(ctx, id)
}

func (a *App) serverConf(ctx context.Context, id int64) (wg.Config, error) {
	serv, err := a.store.GetServer(ctx, id)
	if err != nil {
		return wg.Config{}, err
	}
	clients, err := a.store.ListClients(ctx, id)
	if err != nil {
		return wg.Config{}, err
	}
	return ServerConfig(serv, clients)
}
