package vpn

import (
	"time"

	"github.com/uhiddename/reloc/internal/inet"
	"golang.org/x/crypto/ssh"
)

type Host struct {
	ID        int64
	Name      string
	SSH       SSH
	CreatedAt time.Time
}

type SSH struct {
	Addr    inet.Endpoint
	User    string
	HostKey ssh.PublicKey
}
