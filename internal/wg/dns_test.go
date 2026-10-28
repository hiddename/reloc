package wg

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDNSName(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := strings.Repeat(label63+".", 3) + strings.Repeat("a", 61)

	tests := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{name: "lowercase", in: "Example.COM", want: "example.com"},
		{name: "digits in first label", in: "123.com", want: "123.com"},
		{name: "single label", in: "lan", want: "lan"},
		{name: "single char", in: "a", want: "a"},
		{name: "punycode", in: "xn--d1acufc.xn--p1ai", want: "xn--d1acufc.xn--p1ai"},
		{name: "hyphen inside label", in: "my-host.com", want: "my-host.com"},
		{name: "last label digits and hyphen", in: "a.1-2", want: "a.1-2"},
		{name: "label 63", in: label63 + ".com", want: label63 + ".com"},
		{name: "name 253", in: name253, want: name253},

		{name: "empty", in: "", err: ErrInvalidDNSName},
		{name: "dot", in: ".", err: ErrInvalidDNSName},
		{name: "leading dot", in: ".com", err: ErrInvalidDNSName},
		{name: "trailing dot", in: "example.com.", err: ErrInvalidDNSName},
		{name: "empty label", in: "a..com", err: ErrInvalidDNSName},
		{name: "ipv4", in: "1.2.3.4", err: ErrInvalidDNSName},
		{name: "ipv6", in: "::1", err: ErrInvalidDNSName},
		{name: "digits only", in: "123", err: ErrInvalidDNSName},
		{name: "leading hyphen", in: "-a.com", err: ErrInvalidDNSName},
		{name: "trailing hyphen", in: "a-.com", err: ErrInvalidDNSName},
		{name: "underscore", in: "a_b.com", err: ErrInvalidDNSName},
		{name: "space", in: "a b.com", err: ErrInvalidDNSName},
		{name: "kelvin sign", in: "K.com", err: ErrInvalidDNSName},
		{name: "cyrillic", in: "пример.рф", err: ErrInvalidDNSName},
		{name: "label 64", in: label63 + "a.com", err: ErrInvalidDNSName},
		{name: "name 254", in: name253 + "a", err: ErrInvalidDNSName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDNSName(tt.in)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ParseDNSName(%q) err = %v, want %v", tt.in, err, tt.err)
			}
			if got.String() != tt.want {
				t.Errorf("ParseDNSName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
