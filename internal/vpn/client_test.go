package vpn

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestValidateClientName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"phone", true},
		{"Phone-2_a", true},
		{"a", true},
		{strings.Repeat("a", 15), true},
		{"", false},
		{strings.Repeat("a", 16), false},
		{"with space", false},
		{"имя", false},
		{"a;rm", false},
		{"a\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientName(tt.name)
			if tt.ok {
				if err != nil {
					t.Errorf("ValidateClientName(%q) = %v", tt.name, err)
				}
				return
			}
			var invalid *ValidationError
			if !errors.As(err, &invalid) {
				t.Errorf("ValidateClientName(%q) = %v, want *ValidationError", tt.name, err)
			}
		})
	}
}

func TestValidateTunnelNetworks(t *testing.T) {
	p := netip.MustParsePrefix
	tests := []struct {
		name   string
		tunnel []netip.Prefix
		want   string // part of the error; empty means no error
	}{
		{"nil", nil, ""},
		{"empty", []netip.Prefix{}, ""},
		{"full tunnel", []netip.Prefix{p("0.0.0.0/0"), p("::/0")}, ""},
		{"masked", []netip.Prefix{p("10.66.66.0/24"), p("fd42::/64")}, ""},
		{"single host", []netip.Prefix{p("10.66.66.5/32")}, ""},
		{"zero value", []netip.Prefix{{}}, "not valid"},
		{"host bits", []netip.Prefix{p("10.66.66.5/24")}, "want 10.66.66.0/24"},
		{"v6 host bits", []netip.Prefix{p("fd42::5/64")}, "want fd42::/64"},
		{"bad one after a good one", []netip.Prefix{p("10.0.0.0/8"), p("10.66.66.5/24")}, "10.66.66.5/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTunnelNetworks(tt.tunnel)
			if tt.want == "" {
				if err != nil {
					t.Errorf("err = %v", err)
				}
				return
			}
			var invalid *ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("err = %v, want *ValidationError", err)
			}
			if !strings.Contains(invalid.Msg, tt.want) {
				t.Errorf("Msg = %q, want it to contain %q", invalid.Msg, tt.want)
			}
		})
	}
}
