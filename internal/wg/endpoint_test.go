package wg

import (
	"errors"
	"net/netip"
	"testing"
)

func TestEndpointFromAddr(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		port uint16
		want string
		err  error
	}{
		{name: "ipv4", addr: netip.MustParseAddr("1.2.3.4"), port: 51820, want: "1.2.3.4:51820"},
		{name: "ipv6", addr: netip.MustParseAddr("2001:db8::1"), port: 51820, want: "[2001:db8::1]:51820"},
		{name: "ipv4-mapped ipv6", addr: netip.MustParseAddr("::ffff:1.2.3.4"), port: 51820, want: "1.2.3.4:51820"},
		{name: "max port", addr: netip.MustParseAddr("1.2.3.4"), port: 65535, want: "1.2.3.4:65535"},

		{name: "zero port", addr: netip.MustParseAddr("1.2.3.4"), port: 0, err: ErrInvalidEndpoint},
		{name: "zero addr", addr: netip.Addr{}, port: 51820, err: ErrInvalidEndpoint},
		{name: "zone", addr: netip.MustParseAddr("fe80::1%eth0"), port: 51820, err: ErrInvalidEndpoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EndpointFromAddr(tt.addr, tt.port)
			if !errors.Is(err, tt.err) {
				t.Fatalf("EndpointFromAddr(%v, %d) err = %v, want %v", tt.addr, tt.port, err, tt.err)
			}
			if err != nil {
				if !got.IsZero() {
					t.Errorf("EndpointFromAddr(%v, %d) = %v, want zero", tt.addr, tt.port, got)
				}
				return
			}
			if got.String() != tt.want {
				t.Errorf("EndpointFromAddr(%v, %d) = %q, want %q", tt.addr, tt.port, got, tt.want)
			}
		})
	}
}

func TestEndpointFromName(t *testing.T) {
	name, err := ParseDNSName("VPN.Example.com")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		dns  DNSName
		port uint16
		want string
		err  error
	}{
		{name: "name", dns: name, port: 51820, want: "vpn.example.com:51820"},

		{name: "zero port", dns: name, port: 0, err: ErrInvalidEndpoint},
		{name: "zero name", dns: DNSName{}, port: 51820, err: ErrInvalidEndpoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EndpointFromName(tt.dns, tt.port)
			if !errors.Is(err, tt.err) {
				t.Fatalf("EndpointFromName(%v, %d) err = %v, want %v", tt.dns, tt.port, err, tt.err)
			}
			if err != nil {
				if !got.IsZero() {
					t.Errorf("EndpointFromName(%v, %d) = %v, want zero", tt.dns, tt.port, got)
				}
				return
			}
			if got.String() != tt.want {
				t.Errorf("EndpointFromName(%v, %d) = %q, want %q", tt.dns, tt.port, got, tt.want)
			}
		})
	}
}

func TestEndpointIsZero(t *testing.T) {
	if !(Endpoint{}).IsZero() {
		t.Error("Endpoint{}.IsZero() = false, want true")
	}
	e, err := EndpointFromAddr(netip.MustParseAddr("1.2.3.4"), 51820)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsZero() {
		t.Errorf("%v.IsZero() = true, want false", e)
	}
}
