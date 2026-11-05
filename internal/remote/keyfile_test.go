package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uhiddename/reloc/internal/vpn"
	"golang.org/x/crypto/ssh"
)

func newPrivateKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// writeKeyFile sets the mode explicitly: WriteFile alone depends on the umask.
func writeKeyFile(t *testing.T, data []byte, mode fs.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deploy_key")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func encodeKey(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestKeyFileAuth(t *testing.T) {
	for _, mode := range []fs.FileMode{0o600, 0o400} {
		t.Run(mode.String(), func(t *testing.T) {
			pub, priv := newPrivateKey(t)
			sshPub, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			srv := startServer(t, sshPub, ssh.KeyAlgoED25519)

			auth, err := KeyFileAuth(writeKeyFile(t, encodeKey(t, priv), mode))
			if err != nil {
				t.Fatal(err)
			}

			// the only proof that the right key was loaded is a real login
			c, err := Dial(context.Background(), vpn.SSH{
				Addr:    srv.addr,
				User:    "root",
				HostKey: srv.hostKeys[ssh.KeyAlgoED25519].PublicKey(),
			}, auth)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			out, err := c.Run(context.Background(), "hello", nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != "hello\n" {
				t.Errorf("output = %q", out)
			}
		})
	}
}

func TestKeyFileAuthOpenPermissions(t *testing.T) {
	_, priv := newPrivateKey(t)
	data := encodeKey(t, priv)
	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o660, 0o601, 0o610} {
		t.Run(mode.String(), func(t *testing.T) {
			path := writeKeyFile(t, data, mode)
			auth, err := KeyFileAuth(path)
			if err == nil {
				t.Fatalf("KeyFileAuth() = %v, want an error", auth)
			}
			if !strings.Contains(err.Error(), "too open") || !strings.Contains(err.Error(), path) {
				t.Errorf("err = %v, want the path and a permissions message", err)
			}
		})
	}
}

func TestKeyFileAuthMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-key")
	_, err := KeyFileAuth(path)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestKeyFileAuthGarbage(t *testing.T) {
	const content = "this is not a private key"
	path := writeKeyFile(t, []byte(content), 0o600)
	_, err := KeyFileAuth(path)
	if err == nil {
		t.Fatal("KeyFileAuth() succeeded")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want the path", err)
	}
	if strings.Contains(err.Error(), content) {
		t.Errorf("err reveals the file content: %v", err)
	}
}

func TestKeyFileAuthPassphrase(t *testing.T) {
	_, priv := newPrivateKey(t)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	path := writeKeyFile(t, pem.EncodeToMemory(block), 0o600)

	_, err = KeyFileAuth(path)
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); !ok {
		t.Errorf("err = %v, want PassphraseMissingError", err)
	}
}
