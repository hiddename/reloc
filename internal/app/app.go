package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"

	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/store"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
	"golang.org/x/crypto/ssh"
)

const createClientAttempts = 10

var ErrNoAuth = errors.New("ssh key is not configured")

type App struct {
	store      *store.Store
	auth       ssh.AuthMethod
	applyLocks serverLocks
}

func New(s *store.Store) *App {
	return &App{store: s}
}

func NewAuth(s *store.Store, auth ssh.AuthMethod) *App {
	return &App{store: s, auth: auth}
}

func (a *App) CreateClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	c, err := a.createClient(ctx, serverID, name, tunnel)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: create client: %w", err)
	}
	return c, nil
}

func (a *App) createClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	if err := vpn.ValidateClientName(name); err != nil {
		return vpn.Client{}, err
	}
	if err := vpn.ValidateTunnelNetworks(tunnel); err != nil {
		return vpn.Client{}, err
	}
	var (
		c   vpn.Client
		err error
	)
	for range createClientAttempts {
		c, err = a.tryCreateClient(ctx, serverID, name, tunnel)
		if !errors.Is(err, store.ErrClientAddressTaken) {
			return c, err
		}
	}
	return vpn.Client{}, fmt.Errorf(
		"address conflict persisted after %d attempts, try again: %w",
		createClientAttempts, err,
	)
}

func (a *App) tryCreateClient(ctx context.Context, serverID int64, name string, tunnel []netip.Prefix) (vpn.Client, error) {
	var zero vpn.Client
	serv, err := a.store.GetServer(ctx, serverID)
	if err != nil {
		return zero, err
	}
	if _, err = serv.WireGuard(); err != nil {
		return zero, err
	}
	clients, err := a.store.ListClients(ctx, serverID)
	if err != nil {
		return zero, err
	}
	ipv4, err := allocAddr(
		serv.IPv4, clients,
		func(c vpn.Client) netip.Addr { return c.IPv4 },
	)
	if err != nil {
		return zero, err
	}
	ipv6, err := allocAddr(
		serv.IPv6, clients,
		func(c vpn.Client) netip.Addr { return c.IPv6 },
	)
	if err != nil {
		return zero, err
	}
	if len(tunnel) == 0 {
		tunnel = wg.DefaultAllowedIPs()
	}
	newClient := vpn.Client{
		ServerID:       serverID,
		Name:           name,
		IPv4:           ipv4,
		IPv6:           ipv6,
		TunnelNetworks: tunnel,
		Enabled:        true,
		Protocol: vpn.WireGuardClient{
			PrivateKey:          wg.Genkey(),
			PresharedKey:        wg.Genpsk(),
			PersistentKeepalive: wg.DefaultPersistentKeepalive,
		},
	}
	return a.store.CreateClient(ctx, newClient)
}

func (a *App) ListClients(ctx context.Context, serverID int64) ([]vpn.Client, error) {
	if _, err := a.store.GetServer(ctx, serverID); err != nil {
		return nil, fmt.Errorf("app: list clients: %w", err)
	}
	clients, err := a.store.ListClients(ctx, serverID)
	if err != nil {
		return nil, fmt.Errorf("app: list clients: %w", err)
	}
	return clients, nil
}

func (a *App) DeleteClient(ctx context.Context, clientID int64) error {
	if err := a.deleteClient(ctx, clientID); err != nil {
		return fmt.Errorf("app: delete client: %w", err)
	}
	return nil
}

func (a *App) deleteClient(ctx context.Context, clientID int64) error {
	return a.store.DeleteClient(ctx, clientID)
}

func (a *App) SetClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	if err := a.setClientEnabled(ctx, clientID, enabled); err != nil {
		return fmt.Errorf("app: set client enabled: %w", err)
	}
	return nil
}

func (a *App) setClientEnabled(ctx context.Context, clientID int64, enabled bool) error {
	return a.store.SetClientEnabled(ctx, clientID, enabled)
}

func (a *App) GetClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	c, err := a.getClientByName(ctx, serverID, name)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: get client by name: %w", err)
	}
	return c, nil
}

func (a *App) getClientByName(ctx context.Context, serverID int64, name string) (vpn.Client, error) {
	return a.store.GetClientByName(ctx, serverID, name)
}

func (a *App) GetClient(ctx context.Context, id int64) (vpn.Client, error) {
	c, err := a.getClient(ctx, id)
	if err != nil {
		return vpn.Client{}, fmt.Errorf("app: get client: %w", err)
	}
	return c, nil
}

func (a *App) getClient(ctx context.Context, id int64) (vpn.Client, error) {
	return a.store.GetClient(ctx, id)
}

func (a *App) GetServer(ctx context.Context, id int64) (vpn.Server, error) {
	c, err := a.getServer(ctx, id)
	if err != nil {
		return vpn.Server{}, fmt.Errorf("app: get server: %w", err)
	}
	return c, nil
}

func (a *App) getServer(ctx context.Context, id int64) (vpn.Server, error) {
	return a.store.GetServer(ctx, id)
}

func (a *App) ClientConf(ctx context.Context, id int64) (wg.Config, error) {
	conf, err := a.clientConf(ctx, id)
	if err != nil {
		return wg.Config{}, fmt.Errorf("app: client conf: %w", err)
	}
	return conf, nil
}

func (a *App) clientConf(ctx context.Context, id int64) (wg.Config, error) {
	var zero wg.Config
	client, err := a.getClient(ctx, id)
	if err != nil {
		return zero, err
	}
	serv, err := a.getServer(ctx, client.ServerID)
	if err != nil {
		return zero, err
	}
	conf, err := ClientConfig(serv, client)
	if err != nil {
		return zero, err
	}
	return conf, nil
}

type ApplyAction int

const (
	ApplyUnchanged ApplyAction = iota // config on the host is already up to date
	ApplyCreated                      // interface was not running: written and started
	ApplyRestarted                    // [Interface] changed: written and restarted
	ApplySynced                       // only peers changed: written and synced
)

func (a ApplyAction) String() string {
	switch a {
	case ApplyUnchanged:
		return "unchanged"
	case ApplyCreated:
		return "created"
	case ApplyRestarted:
		return "restarted"
	case ApplySynced:
		return "synced"
	default:
		return fmt.Sprintf("ApplyAction(%d)", int(a))
	}
}

func (a *App) ApplyServer(ctx context.Context, serverID int64) (ApplyAction, error) {
	action, err := a.applyServer(ctx, serverID)
	if err != nil {
		return action, fmt.Errorf("app: apply server: %w", err)
	}
	return action, nil
}

func (a *App) applyServer(ctx context.Context, serverID int64) (ApplyAction, error) {
	if a.auth == nil {
		return ApplyUnchanged, ErrNoAuth
	}
	unlock, err := a.applyLocks.lock(ctx, serverID)
	if err != nil {
		return ApplyUnchanged, err
	}
	defer unlock()
	// read after taking the lock: a waiting apply must see the changes made
	// while it waited, or it would overwrite a newer config with an older one
	serv, err := a.store.GetServer(ctx, serverID)
	if err != nil {
		return ApplyUnchanged, err
	}
	host, err := a.store.GetHost(ctx, serv.HostID)
	if err != nil {
		return ApplyUnchanged, err
	}
	clients, err := a.store.ListClients(ctx, serverID)
	if err != nil {
		return ApplyUnchanged, err
	}
	conf, err := ServerConfig(serv, clients)
	if err != nil {
		return ApplyUnchanged, err
	}
	rc, err := remote.Dial(ctx, host.SSH, a.auth)
	if err != nil {
		return ApplyUnchanged, err
	}
	defer func() { _ = rc.Close() }()
	return applyConfig(ctx, rc, serv, conf)
}

type runner interface {
	Run(ctx context.Context, cmd string, stdin io.Reader) ([]byte, error)
}

type hostState struct {
	ifaceUp    bool
	unitActive bool
	conf       []byte
}

func applyConfig(ctx context.Context, r runner, serv vpn.Server, conf wg.Config) (ApplyAction, error) {
	var buf bytes.Buffer
	if err := wg.Render(&buf, conf); err != nil {
		return ApplyUnchanged, err
	}
	var (
		next  = buf.Bytes()
		iface = serv.InterfaceName
	)
	if _, err := r.Run(ctx, "nft -c -f -", strings.NewReader(nftRuleset(serv))); err != nil {
		return ApplyUnchanged, err
	}
	st, err := readHostState(ctx, r, iface)
	if err != nil {
		return ApplyUnchanged, err
	}
	action, err := planApply(st, iface, next)
	if err != nil {
		return ApplyUnchanged, err
	}
	activate := activateCmd(action, iface)
	if action != ApplyUnchanged {
		path := confPath(iface)
		tmp := path + ".tmp"
		if _, err := r.Run(ctx, "umask 077 && cat > "+tmp, bytes.NewReader(next)); err != nil {
			return ApplyUnchanged, err
		}
		activate = "mv -f " + tmp + " " + path + " && " + activate
	}
	if _, err := r.Run(ctx, activate, nil); err != nil {
		return ApplyUnchanged, err
	}
	return action, nil
}

func readHostState(ctx context.Context, r runner, iface string) (hostState, error) {
	var st hostState
	out, err := r.Run(ctx, "test -e /sys/class/net/"+iface+" && echo up || echo down", nil)
	if err != nil {
		return st, err
	}
	st.ifaceUp = string(bytes.TrimSpace(out)) == "up"

	out, err = r.Run(ctx, "systemctl is-active wg-quick@"+iface+" || true", nil)
	if err != nil {
		return st, err
	}
	st.unitActive = string(bytes.TrimSpace(out)) == "active"

	path := confPath(iface)
	st.conf, err = r.Run(ctx, "if [ -e "+path+" ]; then cat "+path+"; fi", nil)
	return st, err
}

func planApply(st hostState, iface string, next []byte) (ApplyAction, error) {
	switch {
	case st.ifaceUp && !st.unitActive:
		return ApplyUnchanged, fmt.Errorf(
			"interface %s is up but not managed by systemd; run %q first",
			iface, "wg-quick down "+iface,
		)
	case !st.unitActive:
		return ApplyCreated, nil
	case !st.ifaceUp:
		return ApplyRestarted, nil
	case bytes.Equal(st.conf, next):
		return ApplyUnchanged, nil
	case !bytes.Equal(confInterfaceSection(st.conf), confInterfaceSection(next)):
		return ApplyRestarted, nil
	default:
		return ApplySynced, nil
	}
}

func activateCmd(a ApplyAction, iface string) string {
	switch a {
	case ApplyCreated:
		return "systemctl enable --now wg-quick@" + iface
	case ApplyRestarted:
		return "systemctl restart wg-quick@" + iface
	default:
		return fmt.Sprintf("bash -c 'wg syncconf %s <(wg-quick strip %s)'", iface, iface)
	}
}

func confPath(iface string) string {
	return "/etc/wireguard/" + iface + ".conf"
}

func confInterfaceSection(conf []byte) []byte {
	before, _, _ := bytes.Cut(conf, []byte("\n[Peer]"))
	return bytes.TrimSpace(before)
}

// serverLocks serializes applies per server. A lock is a channel, not a
// sync.Mutex, so that waiting for it stops when ctx is canceled.
type serverLocks struct {
	mu    sync.Mutex
	locks map[int64]chan struct{}
}

func (l *serverLocks) lock(ctx context.Context, id int64) (unlock func(), err error) {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[int64]chan struct{})
	}
	ch, ok := l.locks[id]
	if !ok {
		ch = make(chan struct{}, 1)
		l.locks[id] = ch
	}
	l.mu.Unlock()

	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
