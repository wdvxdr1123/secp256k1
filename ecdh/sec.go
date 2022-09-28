// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh

import (
	"encoding/binary"
	"errors"
	"io"
	"math/bits"

	"github.com/wdvxdr1123/secp256k1"
)

type SecCurve[T Point[T]] struct {
	name        string
	newPoint    func() T
	scalarOrder []byte
}

// Point is a generic constraint for the nistec Point types.
type Point[T any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (T, error)
	ScalarMult(T, []byte) (T, error)
	ScalarBaseMult([]byte) (T, error)
}

func (c *SecCurve[Point]) String() string {
	return c.name
}

var errInvalidPrivateKey = errors.New("crypto/ecdh: invalid private key")

func (c *SecCurve[Point]) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	key := make([]byte, len(c.scalarOrder))
	for {
		if _, err := io.ReadFull(rand, key); err != nil {
			return nil, err
		}

		// In tests, rand will return all zeros and NewPrivateKey will reject
		// the zero key as it generates the identity as a public key. This also
		// makes this function consistent with crypto/elliptic.GenerateKey.
		key[1] ^= 0x42

		k, err := c.NewPrivateKey(key)
		if err == errInvalidPrivateKey {
			continue
		}
		return k, err
	}
}

func (c *SecCurve[Point]) NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != len(c.scalarOrder) {
		return nil, errors.New("crypto/ecdh: invalid private key size")
	}
	if isZero(key) || !isLess(key, c.scalarOrder) {
		return nil, errInvalidPrivateKey
	}
	return &PrivateKey{
		curve:      c,
		privateKey: append([]byte{}, key...),
	}, nil
}

func (c *SecCurve[Point]) privateKeyToPublicKey(key *PrivateKey) *PublicKey {
	if key.curve != c {
		panic("crypto/ecdh: internal error: converting the wrong key type")
	}
	p, err := c.newPoint().ScalarBaseMult(key.privateKey)
	if err != nil {
		// This is unreachable because the only error condition of
		// ScalarBaseMult is if the input is not the right size.
		panic("crypto/ecdh: internal error: nistec ScalarBaseMult failed for a fixed-size input")
	}
	publicKey := p.Bytes()
	if len(publicKey) == 1 {
		// The encoding of the identity is a single 0x00 byte. This is
		// unreachable because the only scalar that generates the identity is
		// zero, which is rejected by NewPrivateKey.
		panic("crypto/ecdh: internal error: nistec ScalarBaseMult returned the identity")
	}
	return &PublicKey{
		curve:     key.curve,
		publicKey: publicKey,
	}
}

// isZero returns whether a is all zeroes in constant time.
func isZero(a []byte) bool {
	var acc byte
	for _, b := range a {
		acc |= b
	}
	return acc == 0
}

// isLess returns whether a < b, where a and b are big-endian buffers of the
// same length and shorter than 72 bytes.
func isLess(a, b []byte) bool {
	if len(a) != len(b) {
		panic("crypto/ecdh: internal error: mismatched isLess inputs")
	}

	// Copy the values into a fixed-size preallocated little-endian buffer.
	// 72 bytes is enough for every scalar in this package, and having a fixed
	// size lets us avoid heap allocations.
	if len(a) > 72 {
		panic("crypto/ecdh: internal error: isLess input too large")
	}
	bufA, bufB := make([]byte, 72), make([]byte, 72)
	for i := range a {
		bufA[i], bufB[i] = a[len(a)-i-1], b[len(b)-i-1]
	}

	// Perform a subtraction with borrow.
	var borrow uint64
	for i := 0; i < len(bufA); i += 8 {
		limbA, limbB := binary.LittleEndian.Uint64(bufA[i:]), binary.LittleEndian.Uint64(bufB[i:])
		_, borrow = bits.Sub64(limbA, limbB, borrow)
	}

	// If there is a borrow at the end of the operation, then a < b.
	return borrow == 1
}

func (c *SecCurve[Point]) NewPublicKey(key []byte) (*PublicKey, error) {
	// Reject the point at infinity and compressed encodings.
	if len(key) == 0 || key[0] != 4 {
		return nil, errors.New("crypto/ecdh: invalid public key")
	}
	// SetBytes also checks that the point is on the SecCurve.
	if _, err := c.newPoint().SetBytes(key); err != nil {
		return nil, err
	}

	return &PublicKey{
		curve:     c,
		publicKey: append([]byte{}, key...),
	}, nil
}

func (c *SecCurve[Point]) ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error) {
	p, err := c.newPoint().SetBytes(remote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p.ScalarMult(p, local.privateKey); err != nil {
		return nil, err
	}
	// BytesX will return an error if p is the point at infinity.
	return p.BytesX()
}

// S256 returns a SecCurve which implements secp256k1.
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
func S256() Curve { return s256 }

var s256 = &SecCurve[*secp.P256K1Point]{
	name:        "S-256",
	newPoint:    secp.NewP256K1Point,
	scalarOrder: s256Order,
}

var s256Order = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
