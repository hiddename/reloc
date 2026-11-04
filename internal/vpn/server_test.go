package vpn

import (
	"net/netip"
	"testing"
)

func TestParseNetwork(t *testing.T) {
	tests := []struct {
		in         string
		wantPrefix string
		wantAddr   string
		wantErr    bool
	}{
		{in: "10.66.66.1/24", wantPrefix: "10.66.66.0/24", wantAddr: "10.66.66.1"},
		{in: "10.66.66.254/24", wantPrefix: "10.66.66.0/24", wantAddr: "10.66.66.254"},
		{in: "10.66.0.1/16", wantPrefix: "10.66.0.0/16", wantAddr: "10.66.0.1"},
		{in: "fd42::1/64", wantPrefix: "fd42::/64", wantAddr: "fd42::1"},

		{in: "10.66.66.0/24", wantErr: true}, // network address
		{in: "fd42::/64", wantErr: true},     // network address
		{in: "10.66.66.1", wantErr: true},    // no prefix length
		{in: "10.66.66.1/33", wantErr: true}, // prefix too long
		{in: "fe80::1%eth0/64", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseNetwork(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseNetwork(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil {
			if got != nil {
				t.Errorf("ParseNetwork(%q) = %+v, want nil", tt.in, got)
			}
			continue
		}
		want := Network{
			Prefix: netip.MustParsePrefix(tt.wantPrefix),
			Addr:   netip.MustParseAddr(tt.wantAddr),
		}
		if *got != want {
			t.Errorf("ParseNetwork(%q) = %+v, want %+v", tt.in, *got, want)
		}
	}
}
