// Copyright 2022 The secp256k1 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secp256k1

import (
	"crypto/subtle"
	"errors"
)

// Element is an integer modulo 2^256 - 2^32 - 977.
//
// The zero value is a valid zero element.
type Element [4]uint64

// One sets e = 1, and returns e.
func (e *Element) One() *Element {
	e[0] = 0x1000003d1
	e[1] = uint64(0x0)
	e[2] = uint64(0x0)
	e[3] = uint64(0x0)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *Element) Equal(t *Element) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *Element) IsZero() int {
	zero := make([]byte, ElementLength)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *Element) Set(t *Element) *Element {
	*e = *t
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *Element) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [ElementLength]byte
	return e.bytes(&out)
}

func (e *Element) bytes(out *[ElementLength]byte) []byte {
	var tmp Element
	fromMontgomery(&tmp, e)
	toBytes(out, &tmp)
	invertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^32 - 977,
// SetBytes returns nil and an error, and e is unchanged.
func (e *Element) SetBytes(v []byte) (*Element, error) {
	if len(v) != ElementLength {
		return nil, errors.New("invalid Element encoding")
	}

	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	minusOneEncoding := new(Element).Sub(
		new(Element), new(Element).One()).Bytes()
	for i := range v {
		if v[i] < minusOneEncoding[i] {
			break
		}
		if v[i] > minusOneEncoding[i] {
			return nil, errors.New("invalid Element encoding")
		}
	}

	var in [ElementLength]byte
	copy(in[:], v)
	invertEndianness(in[:])
	var tmp Element
	fromBytes(&tmp, &in)
	toMontgomery(e, &tmp)
	return e, nil
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (e *Element) Select(a, b *Element, cond int) *Element {
	condition := uint64(cond)
	e[0] = cmovznz(condition, b[0], a[0])
	e[1] = cmovznz(condition, b[1], a[1])
	e[2] = cmovznz(condition, b[2], a[2])
	e[3] = cmovznz(condition, b[3], a[3])
	return e
}

func invertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}

// Invert sets e = 1/X, and returns e.
//
// If X == 0, Invert returns e = 0.
func (e *Element) Invert(x *Element) *Element {
	// Inversion is implemented as exponentiation with exponent p − 2.
	// The sequence of 15 multiplications and 255 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10     = 2*1
	//	_100    = 2*_10
	//	_101    = 1 + _100
	//	_111    = _10 + _101
	//	_1110   = 2*_111
	//	_111000 = _1110 << 2
	//	_111111 = _111 + _111000
	//	i13     = _111111 << 4 + _1110
	//	x12     = i13 << 2 + _111
	//	x22     = x12 << 10 + i13 + 1
	//	i29     = 2*x22
	//	i31     = i29 << 2
	//	i54     = i31 << 22 + i31
	//	i122    = (i54 << 20 + i29) << 46 + i54
	//	x223    = i122 << 110 + i122 + _111
	//	i269    = ((x223 << 23 + x22) << 7 + _101) << 3
	//	return    _101 + i269
	//

	var z = new(Element).Set(e)
	var t0 = new(Element)
	var t1 = new(Element)
	var t2 = new(Element)
	var t3 = new(Element)
	var t4 = new(Element)

	t0.Square(x)
	z.Square(t0)
	z.Mul(x, z)
	t1.Mul(t0, z)
	t0.Square(t1)
	t2.Square(t0)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}
	t2.Mul(t1, t2)
	for s := 0; s < 4; s++ {
		t2.Square(t2)
	}
	t0.Mul(t0, t2)
	t2.Square(t0)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}
	t2.Mul(t1, t2)
	for s := 0; s < 10; s++ {
		t2.Square(t2)
	}
	t0.Mul(t0, t2)
	t0.Mul(x, t0)
	t3.Square(t0)
	t2.Square(t3)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}
	t4.Square(t2)
	for s := 1; s < 22; s++ {
		t4.Square(t4)
	}
	t2.Mul(t2, t4)
	t4.Square(t2)
	for s := 1; s < 20; s++ {
		t4.Square(t4)
	}
	t3.Mul(t3, t4)
	for s := 0; s < 46; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	t3.Square(t2)
	for s := 1; s < 110; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	t1.Mul(t1, t2)
	for s := 0; s < 23; s++ {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	for s := 0; s < 7; s++ {
		t0.Square(t0)
	}
	t0.Mul(z, t0)
	for s := 0; s < 3; s++ {
		t0.Square(t0)
	}
	z.Mul(z, t0)

	return e.Set(z)
}
