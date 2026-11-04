package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const dialTimeout = 10 * time.Second

type Client struct {
	ssh *ssh.Client
}

func Dial(ctx context.Context, s vpn.SSH, auth ssh.AuthMethod) (*Client, error) {
	c, err := dial(ctx, s, auth)
	if err != nil {
		return nil, fmt.Errorf("remote: dial %s@%s: %w", s.User, s.Addr, err)
	}
	return c, nil
}

func dial(ctx context.Context, s vpn.SSH, auth ssh.AuthMethod) (*Client, error) {
	if auth == nil {
		return nil, errors.New("auth method is not set")
	}
	if s.HostKey == nil {
		return nil, errors.New("host key is not set")
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	addr := s.Addr.String()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	cfg := &ssh.ClientConfig{
		User:              s.User,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   ssh.FixedHostKey(s.HostKey),
		HostKeyAlgorithms: hostKeyAlgorithms(s.HostKey),
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !stop() {
		if err == nil {
			_ = sc.Close()
		}
		return nil, ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Client{ssh: ssh.NewClient(sc, chans, reqs)}, nil
}

func (c *Client) Run(ctx context.Context, cmd string, stdin io.Reader) ([]byte, error) {
	out, err := c.run(ctx, cmd, stdin)
	if err != nil {
		return nil, fmt.Errorf("remote: run %q: %w", cmd, err)
	}
	return out, nil
}

func (c *Client) run(ctx context.Context, cmd string, stdin io.Reader) ([]byte, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdin, sess.Stdout, sess.Stderr = stdin, &stdout, &stderr

	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()

	if err := sess.Run(cmd); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if _, ok := errors.AsType[*ssh.ExitError](err); ok {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func (c *Client) Close() error {
	return c.ssh.Close()
}

func AgentAuth() (ssh.AuthMethod, io.Closer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("remote: ssh-agent: SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("remote: ssh-agent: %w", err)
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn, nil
}

func hostKeyAlgorithms(k ssh.PublicKey) []string {
	if k.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{k.Type()}
}
