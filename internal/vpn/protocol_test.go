package vpn

import (
	"errors"
	"testing"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		in   string
		want Protocol
		err  error
	}{
		{in: "wireguard", want: WireGuard},
		{in: "WireGuard", err: ErrInvalidProtocol},
		{in: "", err: ErrInvalidProtocol},
		{in: "openvpn", err: ErrInvalidProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseProtocol(tt.in)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ParseProtocol(%q) err = %v, want %v", tt.in, err, tt.err)
			}
			if got != tt.want {
				t.Errorf("ParseProtocol(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseTransport(t *testing.T) {
	tests := []struct {
		in   string
		want Transport
		err  error
	}{
		{in: "udp", want: UDP},
		{in: "tcp", want: TCP},
		{in: "UDP", err: ErrInvalidTransport},
		{in: "", err: ErrInvalidTransport},
		{in: "quic", err: ErrInvalidTransport},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseTransport(tt.in)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ParseTransport(%q) err = %v, want %v", tt.in, err, tt.err)
			}
			if got != tt.want {
				t.Errorf("ParseTransport(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
