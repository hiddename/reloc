package wg

import (
	"bytes"
	"errors"
	"slices"
)

const (
	maxDNSNameLength  = 253
	maxDNSLabelLength = 63
)

var ErrInvalidDNSName = errors.New("wg: invalid dns name")

type DNSName struct {
	s string
}

func (n DNSName) String() string {
	return n.s
}

func ParseDNSName(s string) (DNSName, error) {
	var zero DNSName
	if len(s) > maxDNSNameLength {
		return zero, ErrInvalidDNSName
	}
	b := []byte(s)
	labels := bytes.Split(b, []byte{'.'})
	for _, l := range labels {
		if err := parseDNSLabel(l); err != nil {
			return zero, err
		}
	}
	if !slices.ContainsFunc(
		labels[len(labels)-1],
		func(c byte) bool { return c < '0' || c > '9' },
	) {
		return zero, ErrInvalidDNSName
	}
	return DNSName{s: string(b)}, nil
}

func MustParseDNSName(s string) DNSName {
	n, err := ParseDNSName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func parseDNSLabel(l []byte) error {
	if len(l) < 1 || len(l) > maxDNSLabelLength {
		return ErrInvalidDNSName
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return ErrInvalidDNSName
	}
	for p, c := range l {
		switch {
		case c == '-':
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
			l[p] ^= 0x20
		case c >= '0' && c <= '9':
		default:
			return ErrInvalidDNSName
		}
	}
	return nil
}
