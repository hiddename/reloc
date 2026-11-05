package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/uhiddename/reloc/internal/remote"
	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

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

type hostState struct {
	ifaceUp    bool
	unitActive bool
	conf       []byte
}

type runner interface {
	Run(ctx context.Context, cmd string, stdin io.Reader) ([]byte, error)
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
