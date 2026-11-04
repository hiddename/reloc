package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/uhiddename/reloc/internal/vpn"
	"github.com/uhiddename/reloc/internal/wg"
)

const (
	testNftCheck  = "nft -c -f -"
	testIfaceCmd  = "test -e /sys/class/net/wg0 && echo up || echo down"
	testUnitCmd   = "systemctl is-active wg-quick@wg0 || true"
	testCatCmd    = "if [ -e /etc/wireguard/wg0.conf ]; then cat /etc/wireguard/wg0.conf; fi"
	testWriteCmd  = "umask 077 && cat > /etc/wireguard/wg0.conf.tmp"
	testMv        = "mv -f /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf && "
	testEnableCmd = "systemctl enable --now wg-quick@wg0"
	testRestart   = "systemctl restart wg-quick@wg0"
	testSync      = "bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'"
)

// fakeHost is a runner that answers state queries and records every command.
type fakeHost struct {
	ifaceUp bool
	unit    string // systemctl is-active output
	conf    []byte // current config file
	failOn  string // the command that fails
	failErr error

	cmds  []string
	stdin map[string]string // by command
}

func (h *fakeHost) Run(_ context.Context, cmd string, stdin io.Reader) ([]byte, error) {
	h.cmds = append(h.cmds, cmd)
	if stdin != nil {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		if h.stdin == nil {
			h.stdin = map[string]string{}
		}
		h.stdin[cmd] = string(b)
	}
	if cmd == h.failOn {
		return nil, h.failErr
	}
	switch cmd {
	case testIfaceCmd:
		if h.ifaceUp {
			return []byte("up\n"), nil
		}
		return []byte("down\n"), nil
	case testUnitCmd:
		return []byte(h.unit + "\n"), nil
	case testCatCmd:
		return h.conf, nil
	}
	return nil, nil
}

func renderTestConf(t *testing.T, serv vpn.Server, clients ...vpn.Client) ([]byte, wg.Config) {
	t.Helper()
	conf, err := ServerConfig(serv, clients)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := wg.Render(&buf, conf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), conf
}

func TestConfInterfaceSection(t *testing.T) {
	serv := testServer()
	none, _ := renderTestConf(t, serv)
	one, _ := renderTestConf(t, serv, testClient(1, "a", 1, "10.66.66.2"))
	two, _ := renderTestConf(t, serv,
		testClient(1, "a", 1, "10.66.66.2"),
		testClient(2, "b", 2, "10.66.66.3"),
	)

	want := string(bytes.TrimSpace(none))
	if !strings.HasPrefix(want, "[Interface]\n") {
		t.Fatalf("unexpected config start: %.20q", want)
	}
	for name, conf := range map[string][]byte{
		"no peers":            none,
		"one peer":            one,
		"two peers":           two,
		"no blank line":       bytes.Replace(one, []byte("\n\n[Peer]"), []byte("\n[Peer]"), 1),
		"extra blank lines":   bytes.Replace(one, []byte("\n\n[Peer]"), []byte("\n\n\n\n[Peer]"), 1),
		"no trailing newline": bytes.TrimRight(none, "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			got := string(confInterfaceSection(conf))
			if got != want {
				t.Errorf("section differs from the one of a config without peers")
			}
			if strings.Contains(got, "[Peer]") {
				t.Error("section contains [Peer]")
			}
		})
	}
	if got := confInterfaceSection(nil); len(got) != 0 {
		t.Errorf("section of an empty config has %d bytes", len(got))
	}
	// only a header at the start of a line ends the section
	conf := "[Interface]\nPostUp = echo [Peer]\n\n[Peer]\nAllowedIPs = 10.0.0.2/32\n"
	if got, want := string(confInterfaceSection([]byte(conf))), "[Interface]\nPostUp = echo [Peer]"; got != want {
		t.Errorf("section = %q, want %q", got, want)
	}
}

func TestPlanApply(t *testing.T) {
	serv := testServer()
	otherPort := testServer()
	otherPort.ListenPort = 51999
	a := testClient(1, "a", 1, "10.66.66.2")
	b := testClient(2, "b", 2, "10.66.66.3")

	none, _ := renderTestConf(t, serv)
	withA, _ := renderTestConf(t, serv, a)
	withAB, _ := renderTestConf(t, serv, a, b)
	portA, _ := renderTestConf(t, otherPort, a)

	tests := []struct {
		name string
		st   hostState
		next []byte
		want ApplyAction
	}{
		{"nothing there", hostState{}, withA, ApplyCreated},
		{"stopped with a stale file", hostState{conf: portA}, withA, ApplyCreated},
		{"stopped with the same file", hostState{conf: withA}, withA, ApplyCreated},
		{"unit active, interface gone", hostState{unitActive: true, conf: withA}, withA, ApplyRestarted},
		{"same config", hostState{true, true, withA}, withA, ApplyUnchanged},
		{"peer added", hostState{true, true, withA}, withAB, ApplySynced},
		{"peer removed", hostState{true, true, withAB}, withA, ApplySynced},
		{"first peer added", hostState{true, true, none}, withA, ApplySynced},
		{"last peer removed", hostState{true, true, withA}, none, ApplySynced},
		{"interface changed", hostState{true, true, withA}, portA, ApplyRestarted},
		{"interface and peers changed", hostState{true, true, withAB}, portA, ApplyRestarted},
		{"file is missing", hostState{ifaceUp: true, unitActive: true}, withA, ApplyRestarted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := planApply(tt.st, "wg0", tt.next)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("planApply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlanApplyStartedByHand(t *testing.T) {
	_, err := planApply(hostState{ifaceUp: true}, "wg0", []byte("x"))
	if err == nil {
		t.Fatal("planApply() succeeded")
	}
	if !strings.Contains(err.Error(), "wg-quick down wg0") {
		t.Errorf("err = %q, want it to say how to fix this", err)
	}
}

func TestApplyConfigCommands(t *testing.T) {
	serv := testServer()
	otherPort := testServer()
	otherPort.ListenPort = 51999
	a := testClient(1, "a", 1, "10.66.66.2")
	b := testClient(2, "b", 2, "10.66.66.3")

	withA, _ := renderTestConf(t, serv, a)
	portA, _ := renderTestConf(t, otherPort, a)
	next, conf := renderTestConf(t, serv, a, b)
	state := []string{testNftCheck, testIfaceCmd, testUnitCmd, testCatCmd}

	tests := []struct {
		name      string
		host      fakeHost
		want      ApplyAction
		wantCmds  []string
		wantWrite bool
	}{
		{
			name:      "created when inactive",
			host:      fakeHost{unit: "inactive"},
			want:      ApplyCreated,
			wantCmds:  []string{testWriteCmd, testMv + testEnableCmd},
			wantWrite: true,
		},
		{
			name:      "created when failed",
			host:      fakeHost{unit: "failed", conf: withA},
			want:      ApplyCreated,
			wantCmds:  []string{testWriteCmd, testMv + testEnableCmd},
			wantWrite: true,
		},
		{
			name:      "restarted when the interface is gone",
			host:      fakeHost{unit: "active", conf: next},
			want:      ApplyRestarted,
			wantCmds:  []string{testWriteCmd, testMv + testRestart},
			wantWrite: true,
		},
		{
			name:      "restarted when [Interface] changed",
			host:      fakeHost{ifaceUp: true, unit: "active", conf: portA},
			want:      ApplyRestarted,
			wantCmds:  []string{testWriteCmd, testMv + testRestart},
			wantWrite: true,
		},
		{
			name:      "synced when peers changed",
			host:      fakeHost{ifaceUp: true, unit: "active", conf: withA},
			want:      ApplySynced,
			wantCmds:  []string{testWriteCmd, testMv + testSync},
			wantWrite: true,
		},
		{
			name:     "unchanged file is not written but still synced",
			host:     fakeHost{ifaceUp: true, unit: "active", conf: next},
			want:     ApplyUnchanged,
			wantCmds: []string{testSync},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.host
			got, err := applyConfig(context.Background(), &h, serv, conf)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("applyConfig() = %v, want %v", got, tt.want)
			}
			if want := slices.Concat(state, tt.wantCmds); !slices.Equal(h.cmds, want) {
				t.Errorf("commands mismatch\ngot:  %q\nwant: %q", h.cmds, want)
			}
			if got, want := h.stdin[testNftCheck], nftRuleset(serv); got != want {
				t.Errorf("nft -c stdin = %q, want %q", got, want)
			}
			written, ok := h.stdin[testWriteCmd]
			if ok != tt.wantWrite {
				t.Fatalf("config written = %v, want %v", ok, tt.wantWrite)
			}
			if ok && written != string(next) {
				t.Error("written config differs from the rendered one")
			}
		})
	}
}

func TestApplyConfigFailures(t *testing.T) {
	serv := testServer()
	next, conf := renderTestConf(t, serv, testClient(1, "a", 1, "10.66.66.2"))
	boom := errors.New("boom")
	state := []string{testNftCheck, testIfaceCmd, testUnitCmd, testCatCmd}

	tests := []struct {
		name     string
		host     fakeHost
		failOn   string
		wantCmds []string // nothing runs after the failed command
	}{
		{"nft check", fakeHost{unit: "inactive"}, testNftCheck, []string{testNftCheck}},
		{"interface state", fakeHost{unit: "inactive"}, testIfaceCmd, []string{testNftCheck, testIfaceCmd}},
		{"unit state", fakeHost{unit: "inactive"}, testUnitCmd, []string{testNftCheck, testIfaceCmd, testUnitCmd}},
		{"reading config", fakeHost{unit: "inactive"}, testCatCmd, state},
		{"writing config", fakeHost{unit: "inactive"}, testWriteCmd, slices.Concat(state, []string{testWriteCmd})},
		{
			"activating", fakeHost{unit: "inactive"}, testMv + testEnableCmd,
			slices.Concat(state, []string{testWriteCmd, testMv + testEnableCmd}),
		},
		{
			"syncing unchanged", fakeHost{ifaceUp: true, unit: "active", conf: next}, testSync,
			slices.Concat(state, []string{testSync}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.host
			h.failOn, h.failErr = tt.failOn, boom
			_, err := applyConfig(context.Background(), &h, serv, conf)
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want boom", err)
			}
			if !slices.Equal(h.cmds, tt.wantCmds) {
				t.Errorf("commands mismatch\ngot:  %q\nwant: %q", h.cmds, tt.wantCmds)
			}
		})
	}
}

func TestApplyConfigStartedByHand(t *testing.T) {
	serv := testServer()
	_, conf := renderTestConf(t, serv)
	h := fakeHost{ifaceUp: true, unit: "inactive"}

	_, err := applyConfig(context.Background(), &h, serv, conf)
	if err == nil {
		t.Fatal("applyConfig() succeeded")
	}
	// the host stays untouched
	if want := []string{testNftCheck, testIfaceCmd, testUnitCmd, testCatCmd}; !slices.Equal(h.cmds, want) {
		t.Errorf("commands mismatch\ngot:  %q\nwant: %q", h.cmds, want)
	}
}

func TestReadHostState(t *testing.T) {
	tests := []struct {
		unit       string
		wantActive bool
	}{
		{"active", true},
		{"inactive", false},
		{"failed", false},
		{"activating", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.unit, func(t *testing.T) {
			h := fakeHost{ifaceUp: true, unit: tt.unit, conf: []byte("[Interface]\n")}
			st, err := readHostState(context.Background(), &h, "wg0")
			if err != nil {
				t.Fatal(err)
			}
			if !st.ifaceUp || st.unitActive != tt.wantActive || string(st.conf) != "[Interface]\n" {
				t.Errorf("readHostState() = %+v", st)
			}
		})
	}
	t.Run("interface down", func(t *testing.T) {
		h := fakeHost{unit: "inactive"}
		st, err := readHostState(context.Background(), &h, "wg0")
		if err != nil {
			t.Fatal(err)
		}
		if st.ifaceUp {
			t.Error("ifaceUp = true, want false")
		}
	})
}

func TestApplyActionString(t *testing.T) {
	for a, want := range map[ApplyAction]string{
		ApplyUnchanged: "unchanged",
		ApplyCreated:   "created",
		ApplyRestarted: "restarted",
		ApplySynced:    "synced",
	} {
		if got := a.String(); got != want {
			t.Errorf("ApplyAction(%d).String() = %q, want %q", int(a), got, want)
		}
	}
}
