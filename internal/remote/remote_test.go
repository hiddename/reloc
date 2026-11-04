package remote

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

// testServer is an in-process SSH server with a few fake commands:
//
//	hello  prints "hello\n"
//	cat    copies stdin to stdout
//	fail   prints "boom" to stderr and exits with status 3
//	hang   never finishes
type testServer struct {
	addr     inet.Endpoint
	hostKeys map[string]ssh.Signer // by key type
}

func newSigner(t *testing.T, keyType string) ssh.Signer {
	t.Helper()
	var (
		key any
		err error
	)
	switch keyType {
	case ssh.KeyAlgoED25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case ssh.KeyAlgoECDSA256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ssh.KeyAlgoRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("unknown key type %q", keyType)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startServer serves SSH on a random local port with a host key of every
// given type and accepts only the client key.
func startServer(t *testing.T, client ssh.PublicKey, hostKeyTypes ...string) testServer {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), client.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown client key")
		},
	}
	srv := testServer{hostKeys: map[string]ssh.Signer{}}
	for _, typ := range hostKeyTypes {
		s := newSigner(t, typ)
		cfg.AddHostKey(s)
		srv.hostKeys[typ] = s
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go serveConn(c, cfg)
		}
	}()

	srv.addr = inet.MustEndpointFromAddr(
		netip.MustParseAddr("127.0.0.1"),
		uint16(l.Addr().(*net.TCPAddr).Port),
	)
	return srv
}

func serveConn(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveSession(ch, chReqs)
	}
}

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	// the request channel is closed when the client closes the session
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var p struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)
		go exec(ch, p.Command)
	}
}

func exec(ch ssh.Channel, cmd string) {
	status := uint32(0)
	switch cmd {
	case "hello":
		_, _ = io.WriteString(ch, "hello\n")
	case "cat":
		_, _ = io.Copy(ch, ch)
	case "fail":
		_, _ = io.WriteString(ch.Stderr(), "boom\n")
		status = 3
	case "hang":
		return
	default:
		_, _ = io.WriteString(ch.Stderr(), "unknown command\n")
		status = 127
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	_ = ch.Close()
}

type testEnv struct {
	srv  testServer
	user ssh.Signer
}

func newTestEnv(t *testing.T, hostKeyTypes ...string) testEnv {
	t.Helper()
	if len(hostKeyTypes) == 0 {
		hostKeyTypes = []string{ssh.KeyAlgoED25519}
	}
	user := newSigner(t, ssh.KeyAlgoED25519)
	return testEnv{srv: startServer(t, user.PublicKey(), hostKeyTypes...), user: user}
}

// sshFor returns connection settings that trust the server key of keyType.
func (e testEnv) sshFor(keyType string) vpn.SSH {
	return vpn.SSH{
		Addr:    e.srv.addr,
		User:    "root",
		HostKey: e.srv.hostKeys[keyType].PublicKey(),
	}
}

func (e testEnv) dial(t *testing.T) *Client {
	t.Helper()
	c, err := Dial(context.Background(), e.sshFor(ssh.KeyAlgoED25519), ssh.PublicKeys(e.user))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRun(t *testing.T) {
	c := newTestEnv(t).dial(t)

	out, err := c.Run(context.Background(), "hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello\n" {
		t.Errorf("Run() = %q, want %q", out, "hello\n")
	}
}

func TestRunStdin(t *testing.T) {
	c := newTestEnv(t).dial(t)
	in := "[Interface]\nListenPort = 51820\n"

	out, err := c.Run(context.Background(), "cat", strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("Run() = %q, want stdin back %q", out, in)
	}
}

func TestRunSeveralCommands(t *testing.T) {
	c := newTestEnv(t).dial(t)
	ctx := context.Background()

	for range 3 {
		if _, err := c.Run(ctx, "hello", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Run(ctx, "fail", nil); err == nil {
		t.Fatal("Run(fail) succeeded")
	}
	// a failed command does not break the connection
	if _, err := c.Run(ctx, "hello", nil); err != nil {
		t.Fatalf("Run() after a failed command: %v", err)
	}
}

func TestRunExitError(t *testing.T) {
	c := newTestEnv(t).dial(t)

	out, err := c.Run(context.Background(), "fail", nil)
	if err == nil {
		t.Fatalf("Run() = %q, want error", out)
	}
	exitErr, ok := errors.AsType[*ssh.ExitError](err)
	if !ok {
		t.Fatalf("err = %v, want *ssh.ExitError inside", err)
	}
	if exitErr.ExitStatus() != 3 {
		t.Errorf("ExitStatus() = %d, want 3", exitErr.ExitStatus())
	}
	for _, s := range []string{`remote: run "fail"`, "boom"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("err = %q, want it to contain %q", err, s)
		}
	}
	if strings.Contains(err.Error(), "boom\n") {
		t.Errorf("err = %q, stderr is not trimmed", err)
	}
	if out != nil {
		t.Errorf("Run() on error = %q, want nil", out)
	}
}

func TestRunContextCanceled(t *testing.T) {
	c := newTestEnv(t).dial(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Run(ctx, "hang", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Run() returned after %v, want right after the deadline", d)
	}
	// the connection survives a canceled command
	if _, err := c.Run(context.Background(), "hello", nil); err != nil {
		t.Fatalf("Run() after cancel: %v", err)
	}
}

func TestDialHostKeyTypes(t *testing.T) {
	// the server has keys of all types; whichever one is stored must be used
	types := []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSA, ssh.KeyAlgoED25519}
	e := newTestEnv(t, types...)
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			c, err := Dial(context.Background(), e.sshFor(typ), ssh.PublicKeys(e.user))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Run(context.Background(), "hello", nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialHostKeyMismatch(t *testing.T) {
	e := newTestEnv(t)
	s := e.sshFor(ssh.KeyAlgoED25519)
	s.HostKey = newSigner(t, ssh.KeyAlgoED25519).PublicKey()

	c, err := Dial(context.Background(), s, ssh.PublicKeys(e.user))
	if err == nil {
		c.Close()
		t.Fatal("Dial() accepted a server with another host key")
	}
	if !strings.Contains(err.Error(), "host key mismatch") {
		t.Errorf("err = %v, want host key mismatch", err)
	}
}

func TestDialHostKeyTypeMissing(t *testing.T) {
	// the stored key type is one the server does not have
	e := newTestEnv(t, ssh.KeyAlgoED25519)
	s := e.sshFor(ssh.KeyAlgoED25519)
	s.HostKey = newSigner(t, ssh.KeyAlgoECDSA256).PublicKey()

	c, err := Dial(context.Background(), s, ssh.PublicKeys(e.user))
	if err == nil {
		c.Close()
		t.Fatal("Dial() succeeded")
	}
}

func TestDialAuthRejected(t *testing.T) {
	e := newTestEnv(t)
	stranger := newSigner(t, ssh.KeyAlgoED25519)

	c, err := Dial(context.Background(), e.sshFor(ssh.KeyAlgoED25519), ssh.PublicKeys(stranger))
	if err == nil {
		c.Close()
		t.Fatal("Dial() succeeded with an unauthorized key")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("err = %v, want an authentication error", err)
	}
}

func TestDialNoHostKey(t *testing.T) {
	e := newTestEnv(t)
	s := e.sshFor(ssh.KeyAlgoED25519)
	s.HostKey = nil

	c, err := Dial(context.Background(), s, ssh.PublicKeys(e.user))
	if err == nil {
		c.Close()
		t.Fatal("Dial() succeeded without a host key")
	}
	want := "remote: dial root@" + s.Addr.String() + ": host key is not set"
	if err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
}

func TestDialNoAuth(t *testing.T) {
	e := newTestEnv(t)

	c, err := Dial(context.Background(), e.sshFor(ssh.KeyAlgoED25519), nil)
	if err == nil {
		c.Close()
		t.Fatal("Dial() succeeded without an auth method")
	}
	if !strings.Contains(err.Error(), "auth method is not set") {
		t.Errorf("err = %v, want auth method is not set", err)
	}
}

func TestDialHandshakeTimeout(t *testing.T) {
	// accepts TCP but never speaks SSH
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	s := vpn.SSH{
		Addr:    inet.MustEndpointFromAddr(netip.MustParseAddr("127.0.0.1"), uint16(l.Addr().(*net.TCPAddr).Port)),
		User:    "root",
		HostKey: newSigner(t, ssh.KeyAlgoED25519).PublicKey(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := Dial(ctx, s, ssh.PublicKeys(newSigner(t, ssh.KeyAlgoED25519)))
	if err == nil {
		c.Close()
		t.Fatal("Dial() succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Dial() returned after %v, want right after the deadline", d)
	}
}

func TestHostKeyAlgorithms(t *testing.T) {
	tests := []struct {
		keyType string
		want    []string
	}{
		{ssh.KeyAlgoED25519, []string{ssh.KeyAlgoED25519}},
		{ssh.KeyAlgoECDSA256, []string{ssh.KeyAlgoECDSA256}},
		{ssh.KeyAlgoRSA, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}},
	}
	for _, tt := range tests {
		got := hostKeyAlgorithms(newSigner(t, tt.keyType).PublicKey())
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("hostKeyAlgorithms(%s) = %q, want %q", tt.keyType, got, tt.want)
		}
	}
}
