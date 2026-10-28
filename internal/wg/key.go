package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

var ErrInvalidBase64 = errors.New("wg: invalid base64")
var ErrInvalidKeySize = errors.New("wg: invalid key size")

const (
	keySize = 32
)

type (
	PrivateKey   [keySize]byte
	PublicKey    [keySize]byte
	PresharedKey [keySize]byte
)

type Key interface {
	PrivateKey | PublicKey | PresharedKey
}

func randKey[K Key]() (k K) {
	rand.Read(k[:])
	return
}

func keyToBase64[K Key](k K) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func ParseKey[K Key](s string) (K, error) {
	var zero K
	bs, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrInvalidBase64, err)
	}
	if len(bs) != keySize {
		return zero, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKeySize, len(bs), keySize)
	}
	return K(bs), nil
}

func MustParseKey[K Key](s string) K {
	k, err := ParseKey[K](s)
	if err != nil {
		panic(err)
	}
	return k
}

func Genkey() PrivateKey {
	return randKey[PrivateKey]().clamped()
}

func (k PrivateKey) clamped() PrivateKey {
	k[0] &= 0b1111_1000
	k[keySize-1] &= 0b0111_1111
	k[keySize-1] |= 0b0100_0000
	return k
}

func (k PrivateKey) PublicKey() PublicKey {
	p, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		panic(err)
	}
	return PublicKey(p.PublicKey().Bytes())
}

func (k PrivateKey) Base64() string {
	return keyToBase64(k)
}

func (k PrivateKey) String() string {
	return "[redacted]"
}

func Genpsk() PresharedKey {
	return randKey[PresharedKey]()
}

func (k PresharedKey) Base64() string {
	return keyToBase64(k)
}

func (k PresharedKey) String() string {
	return "[redacted]"
}

func (k PublicKey) String() string {
	return keyToBase64(k)
}
