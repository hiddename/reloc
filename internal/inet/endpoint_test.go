package inet

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

func TestEndpointFromHost(t *testing.T) {
	tests := []struct {
		host     string
		port     uint16
		want     string
		wantAddr bool
		wantErr  bool
	}{
		{host: "203.0.113.5", port: 22, want: "203.0.113.5:22", wantAddr: true},
		{host: "2001:db8::1", port: 22, want: "[2001:db8::1]:22", wantAddr: true},
		{host: "vpn.example.com", port: 51820, want: "vpn.example.com:51820"},
		{host: "localhost", port: 22, want: "localhost:22"},

		{host: "", port: 22, wantErr: true},
		{host: "bad_name!", port: 22, wantErr: true},
		{host: "[2001:db8::1]", port: 22, wantErr: true},
		{host: "vpn.example.com", port: 0, wantErr: true},
		{host: "203.0.113.5", port: 0, wantErr: true},
	}
	for _, tt := range tests {
		got, err := EndpointFromHost(tt.host, tt.port)
		if (err != nil) != tt.wantErr {
			t.Errorf("EndpointFromHost(%q, %d) err = %v, wantErr %v", tt.host, tt.port, err, tt.wantErr)
			continue
		}
		if err != nil {
			if !got.IsZero() {
				t.Errorf("EndpointFromHost(%q, %d) = %v, want zero", tt.host, tt.port, got)
			}
			continue
		}
		if got.String() != tt.want {
			t.Errorf("EndpointFromHost(%q, %d) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
		if got.Addr().IsValid() != tt.wantAddr {
			t.Errorf("EndpointFromHost(%q, %d): parsed as address = %v, want %v", tt.host, tt.port, got.Addr().IsValid(), tt.wantAddr)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "203.0.113.5:22", want: "203.0.113.5:22"},
		{in: "[2001:db8::1]:22", want: "[2001:db8::1]:22"},
		{in: "vpn.example.com:51820", want: "vpn.example.com:51820"},
		{in: "203.0.113.5:65535", want: "203.0.113.5:65535"},

		{in: "203.0.113.5", wantErr: true},       // no port
		{in: "2001:db8::1:22", wantErr: true},    // IPv6 without brackets
		{in: "203.0.113.5:65536", wantErr: true}, // port out of range
		{in: "203.0.113.5:-1", wantErr: true},    // negative port
		{in: "203.0.113.5:ssh", wantErr: true},   // service names are not resolved
		{in: "203.0.113.5:0", wantErr: true},     // zero port
		{in: ":22", wantErr: true},               // empty host
		{in: "bad_name!:22", wantErr: true},      // neither IP nor DNS name
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseEndpoint(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseEndpoint(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			if !got.IsZero() {
				t.Errorf("ParseEndpoint(%q) = %v, want zero", tt.in, got)
			}
			continue
		}
		if got.String() != tt.want {
			t.Errorf("ParseEndpoint(%q) = %q, want %q", tt.in, got, tt.want)
		}
		// String and ParseEndpoint are inverse
		again, err := ParseEndpoint(got.String())
		if err != nil || again != got {
			t.Errorf("ParseEndpoint(%q) round trip = %v, %v; want %v", got.String(), again, err, got)
		}
	}
}
