// Copyright 2022 The secp256k1 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secp256k1

import (
	"crypto/subtle"
	"errors"
	"sync"
)

var b, _ = new(Element).SetBytes([]byte{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7,
})

var b3, _ = new(Element).SetBytes([]byte{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x15,
})

var g, _ = NewPoint().SetBytes([]byte{0x4, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0xe, 0x11, 0x8, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8})

// ElementLength is the length of an element of the base or scalar field.
const ElementLength = 32

// Point is a secp256k1 point. The zero value is NOT valid.
type Point struct {
	// The point is represented in projective coordinates (X:Y:Z),
	// where X = X/Z and Y = Y/Z.
	X, Y, Z *Element
}

// NewPoint returns a new Point representing the point at infinity point.
func NewPoint() *Point {
	return &Point{
		X: new(Element),
		Y: new(Element).One(),
		Z: new(Element),
	}
}

// NewGenerator returns a new Point set to the canonical generator.
func NewGenerator() *Point {
	return (&Point{
		X: new(Element),
		Y: new(Element),
		Z: new(Element),
	}).Set(g)
}

// Set sets p = q and returns p.
func (p *Point) Set(q *Point) *Point {
	p.X.Set(q.X)
	p.Y.Set(q.Y)
	p.Z.Set(q.Z)
	return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *Point) SetBytes(b []byte) (_ *Point, e error) {
	switch {
	// Point at infinity.
	case len(b) == 1 && b[0] == 0:
		return p.Set(NewPoint()), nil

	// Uncompressed form.
	case len(b) == 1+2*ElementLength && b[0] == 4:
		x, err := new(Element).SetBytes(b[1 : 1+ElementLength])
		if err != nil {
			return nil, err
		}
		y, err := new(Element).SetBytes(b[1+ElementLength:])
		if err != nil {
			return nil, err
		}
		if err := checkOnCurve(x, y); err != nil {
			return nil, err
		}
		p.X.Set(x)
		p.Y.Set(y)
		p.Z.One()
		return p, nil

	// Compressed form.
	case len(b) == 1+ElementLength && (b[0] == 2 || b[0] == 3):
		x, err := new(Element).SetBytes(b[1:])
		if err != nil {
			return nil, err
		}

		// Y² = X³ + b
		y := polynomial(new(Element), x)
		if !sqrt(y, y) {
			return nil, errors.New("invalid secp256k1 compressed point encoding")
		}

		// Select the positive or negative root, as indicated by the least
		// significant bit, based on the encoding type byte.
		otherRoot := new(Element)
		otherRoot.Sub(otherRoot, y)
		cond := y.Bytes()[ElementLength-1]&1 ^ b[0]&1
		y.Select(otherRoot, y, int(cond))

		p.X.Set(x)
		p.Y.Set(y)
		p.Z.One()
		return p, nil

	default:
		return nil, errors.New("invalid secp256k1 point encoding")
	}
}

// polynomial sets y2 to X³ + b, and returns y2.
func polynomial(y2, x *Element) *Element {
	y2.Square(x)         // y2 := x  * x
	y2.Mul(y2, x)        // y2 := y2 * x
	return y2.Add(y2, b) // y2 := y2 + b
}

func checkOnCurve(x, y *Element) error {
	// Y² = X³ + b
	rhs := polynomial(new(Element), x)
	lhs := new(Element).Square(y)
	if rhs.Equal(lhs) != 1 {
		return errors.New("secp256k1 point not on curve")
	}
	return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + 2*ElementLength]byte
	return p.bytes(&out)
}

func (p *Point) bytes(out *[1 + 2*ElementLength]byte) []byte {
	if p.Z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new(Element).Invert(p.Z)
	x := new(Element).Mul(p.X, zinv)
	y := new(Element).Mul(p.Y, zinv)

	buf := append(out[:0], 4)
	buf = append(buf, x.Bytes()...)
	buf = append(buf, y.Bytes()...)
	return buf
}

// BytesX returns the encoding of the X-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *Point) BytesX() ([]byte, error) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [ElementLength]byte
	return p.bytesX(&out)
}
func (p *Point) bytesX(out *[ElementLength]byte) ([]byte, error) {
	if p.Z.IsZero() == 1 {
		return nil, errors.New("P256K1 point is the point at infinity")
	}
	zinv := new(Element).Invert(p.Z)
	x := new(Element).Mul(p.X, zinv)
	return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *Point) BytesCompressed() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + ElementLength]byte
	return p.bytesCompressed(&out)
}

func (p *Point) bytesCompressed(out *[1 + ElementLength]byte) []byte {
	if p.Z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new(Element).Invert(p.Z)
	x := new(Element).Mul(p.X, zinv)
	y := new(Element).Mul(p.Y, zinv)

	// Encode the sign of the Y coordinate (indicated by the least significant
	// bit) as the encoding type (2 or 3).
	buf := append(out[:0], 2)
	buf[0] |= y.Bytes()[ElementLength-1] & 1
	buf = append(buf, x.Bytes()...)
	return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (p *Point) Add(p1, p2 *Point) *Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.3.

	t0 := new(Element).Mul(p1.X, p2.X) // t0 := X1 * X2
	t1 := new(Element).Mul(p1.Y, p2.Y) // t1 := Y1 * Y2
	t2 := new(Element).Mul(p1.Z, p2.Z) // t2 := Z1 * Z2
	t3 := new(Element).Add(p1.X, p1.Y) // t3 := X1 + Y1
	t4 := new(Element).Add(p2.X, p2.Y) // t4 := X2 + Y2
	t3.Mul(t3, t4)                     // t3 := t3 * t4
	t4.Add(t0, t1)                     // t4 := t0 + t1
	t3.Sub(t3, t4)                     // t3 := t3 - t4
	t4.Add(p1.Y, p1.Z)                 // t4 := Y1 + Z1
	x3 := new(Element).Add(p2.Y, p2.Z) // X3 := Y2 + Z2
	t4.Mul(t4, x3)                     // t4 := t4 * X3
	x3.Add(t1, t2)                     // X3 := t1 + t2
	t4.Sub(t4, x3)                     // t4 := t4 - X3
	x3.Add(p1.X, p1.Z)                 // X3 := X1 + Z1
	y3 := new(Element).Add(p2.X, p2.Z) // Y3 := X2 + Z2
	x3.Mul(x3, y3)                     // X3 := X3 * Y3
	y3.Add(t0, t2)                     // Y3 := t0 + t2
	y3.Sub(x3, y3)                     // Y3 := X3 - Y3
	x3.Add(t0, t0)                     // X3 := t0 + t0
	t0.Add(x3, t0)                     // t0 := X3 + t0
	t2.Mul(b3, t2)                     // t2 := b3 * t2
	z3 := new(Element).Add(t1, t2)     // Z3 := t1 * t2
	t1.Sub(t1, t2)                     // t1 := t1 - t2
	y3.Mul(b3, y3)                     // Y3 := b3 * Y3
	x3.Mul(t4, y3)                     // X3 := t4 * Y3
	t2.Mul(t3, t1)                     // t2 := t3 * t1
	x3.Sub(t2, x3)                     // x3 := t2 - X3
	y3.Mul(y3, t0)                     // Y3 := Y3 * t0
	t1.Mul(t1, z3)                     // t1 := t1 * Z3
	y3.Add(t1, y3)                     // Y3 := t1 + Y3
	t0.Mul(t0, t3)                     // t0 := t0 * t3
	z3.Mul(z3, t4)                     // Z3 := Z3 * t4
	z3.Add(z3, t0)                     // Z3 := Z3 + t0

	p.X.Set(x3)
	p.Y.Set(y3)
	p.Z.Set(z3)
	return p
}

// Sub sets q = p1 - p2, and returns q. The points may overlap.
func (q *Point) Sub(p1, p2 *Point) *Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.3.

	t0 := new(Element).Mul(p1.X, p2.X) // t0 := X1 * X2
	y2 := new(Element)                 // Y2
	y2.Sub(y2, p2.Y)                   // Y2 :=    - Y2
	t1 := new(Element).Mul(p1.Y, y2)   // t1 := Y1 * Y2
	t2 := new(Element).Mul(p1.Z, p2.Z) // t2 := Z1 * Z2
	t3 := new(Element).Add(p1.X, p1.Y) // t3 := X1 + Y1
	t4 := new(Element).Add(p2.X, y2)   // t4 := X2 + Y2
	t3.Mul(t3, t4)                     // t3 := t3 * t4
	t4.Add(t0, t1)                     // t4 := t0 + t1
	t3.Sub(t3, t4)                     // t3 := t3 - t4
	t4.Add(p1.Y, p1.Z)                 // t4 := Y1 + Z1
	x3 := new(Element).Add(y2, p2.Z)   // X3 := Y2 + Z2
	t4.Mul(t4, x3)                     // t4 := t4 * X3
	x3.Add(t1, t2)                     // X3 := t1 + t2
	t4.Sub(t4, x3)                     // t4 := t4 - X3
	x3.Add(p1.X, p1.Z)                 // X3 := X1 + Z1
	y3 := new(Element).Add(p2.X, p2.Z) // Y3 := X2 + Z2
	x3.Mul(x3, y3)                     // X3 := X3 * Y3
	y3.Add(t0, t2)                     // Y3 := t0 + t2
	y3.Sub(x3, y3)                     // Y3 := X3 - Y3
	x3.Add(t0, t0)                     // X3 := t0 + t0
	t0.Add(x3, t0)                     // t0 := X3 + t0
	t2.Mul(b3, t2)                     // t2 := b3 * t2
	z3 := new(Element).Add(t1, t2)     // Z3 := t1 * t2
	t1.Sub(t1, t2)                     // t1 := t1 - t2
	y3.Mul(b3, y3)                     // Y3 := b3 * Y3
	x3.Mul(t4, y3)                     // X3 := t4 * Y3
	t2.Mul(t3, t1)                     // t2 := t3 * t1
	x3.Sub(t2, x3)                     // x3 := t2 - X3
	y3.Mul(y3, t0)                     // Y3 := Y3 * t0
	t1.Mul(t1, z3)                     // t1 := t1 * Z3
	y3.Add(t1, y3)                     // Y3 := t1 + Y3
	t0.Mul(t0, t3)                     // t0 := t0 * t3
	z3.Mul(z3, t4)                     // Z3 := Z3 * t4
	z3.Add(z3, t0)                     // Z3 := Z3 + t0

	q.X.Set(x3)
	q.Y.Set(y3)
	q.Z.Set(z3)
	return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *Point) Double(p *Point) *Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.3.

	t0 := new(Element).Square(p.Y)   // t0 := Y^2
	z3 := new(Element).Add(t0, t0)   // Z3 := t0 + t0
	z3.Add(z3, z3)                   // Z3 := Z3 + Z3
	z3.Add(z3, z3)                   // Z3 := Z3 + Z3
	t1 := new(Element).Mul(p.Y, p.Z) // t1 := Y  * Z
	t2 := new(Element).Square(p.Z)   // t2 := Z^2
	t2.Mul(b3, t2)                   // t2 := b3 * t2
	x3 := new(Element).Mul(t2, z3)   // X3 := t2 * Z3
	y3 := new(Element).Add(t0, t2)   // Y3 := t0 + t2
	z3.Mul(t1, z3)                   // Z3 := t1 * Z3
	t1.Add(t2, t2)                   // t1 := t2 + t2
	t2.Add(t1, t2)                   // t2 := t1 + t2
	t0.Sub(t0, t2)                   // t0 := t0 - t2
	y3.Mul(t0, y3)                   // Y3 := t0 * Y3
	y3.Add(x3, y3)                   // Y3 := X3 + Y3
	t1.Mul(p.X, p.Y)                 // t1 := X  * Y
	x3.Mul(t0, t1)                   // X3 := t0 * t1
	x3.Add(x3, x3)                   // X3 := X3 + X3

	p.X.Set(x3)
	p.Y.Set(y3)
	p.Z.Set(z3)
	return p
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (p *Point) Select(p1, p2 *Point, cond int) *Point {
	p.X.Select(p1.X, p2.X, cond)
	p.Y.Select(p1.Y, p2.Y, cond)
	p.Z.Select(p1.Z, p2.Z, cond)
	return p
}

// A table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type table [15]*Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *table) Select(p *Point, n uint8) {
	if n >= 16 {
		panic("secp256k1: internal error: table called with out-of-bounds value")
	}
	p.Set(NewPoint())
	for i := uint8(1); i < 16; i++ {
		cond := subtle.ConstantTimeByteEq(i, n)
		p.Select(table[i-1], p, cond)
	}
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *Point) ScalarMult(q *Point, scalar []byte) (*Point, error) {
	// Compute a table for the base point q. The explicit NewPoint
	// calls get inlined, letting the allocations live on the stack.
	var table = table{NewPoint(), NewPoint(), NewPoint(),
		NewPoint(), NewPoint(), NewPoint(), NewPoint(),
		NewPoint(), NewPoint(), NewPoint(), NewPoint(),
		NewPoint(), NewPoint(), NewPoint(), NewPoint()}
	table[0].Set(q)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], q)
	}

	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := NewPoint()
	p.Set(NewPoint())
	for i, byte := range scalar {
		// No need to double on the first iteration, as p is the identity at
		// this point, and [N]∞ = ∞.
		if i != 0 {
			p.Double(p)
			p.Double(p)
			p.Double(p)
			p.Double(p)
		}

		windowValue := byte >> 4
		table.Select(t, windowValue)
		p.Add(p, t)

		p.Double(p)
		p.Double(p)
		p.Double(p)
		p.Double(p)

		windowValue = byte & 0b1111
		table.Select(t, windowValue)
		p.Add(p, t)
	}

	return p, nil
}

var generatorTable *[ElementLength * 2]table
var generatorTableOnce sync.Once

// generatorTable returns a sequence of tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *Point) generatorTable() *[ElementLength * 2]table {
	generatorTableOnce.Do(func() {
		generatorTable = new([ElementLength * 2]table)
		base := NewGenerator()
		for i := 0; i < ElementLength*2; i++ {
			generatorTable[i][0] = NewPoint().Set(base)
			for j := 1; j < 15; j++ {
				generatorTable[i][j] = NewPoint().Add(generatorTable[i][j-1], base)
			}
			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return generatorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *Point) ScalarBaseMult(scalar []byte) (*Point, error) {
	if len(scalar) != ElementLength {
		return nil, errors.New("invalid scalar length")
	}
	tables := p.generatorTable()

	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := NewPoint()
	p.Set(NewPoint())
	tableIndex := len(tables) - 1
	for _, byte := range scalar {
		windowValue := byte >> 4
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--

		windowValue = byte & 0b1111
		tables[tableIndex].Select(t, windowValue)
		p.Add(p, t)
		tableIndex--
	}

	return p, nil
}

// sqrt sets e to a square root of X. If X is not a square, sqrt returns
// false and e is unchanged. e and X can overlap.
func sqrt(e, x *Element) (isSquare bool) {
	candidate := new(Element)
	sqrtCandidate(candidate, x)
	square := new(Element).Square(candidate)
	if square.Equal(x) != 1 {
		return false
	}
	e.Set(candidate)
	return true
}

// sqrtCandidate sets Z to a square root candidate for X. Z and X must not overlap.
func sqrtCandidate(z, x *Element) {
	// Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
	//
	// The sequence of 13 multiplications and 253 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1111    = _11 + _1100
	//	_11110   = 2*_1111
	//	_11111   = 1 + _11110
	//	_1111100 = _11111 << 2
	//	_1111111 = _11 + _1111100
	//	x11      = _1111111 << 4 + _1111
	//	x22      = x11 << 11 + x11
	//	x27      = x22 << 5 + _11111
	//	x54      = x27 << 27 + x27
	//	x108     = x54 << 54 + x54
	//	x216     = x108 << 108 + x108
	//	x223     = x216 << 7 + _1111111
	//	return     ((x223 << 23 + x22) << 6 + _11) << 2
	//
	var t0 = new(Element)
	var t1 = new(Element)
	var t2 = new(Element)
	var t3 = new(Element)

	z.Square(x)
	z.Mul(x, z)
	t0.Square(z)
	for s := 1; s < 2; s++ {
		t0.Square(t0)
	}
	t0.Mul(z, t0)
	t1.Square(t0)
	t2.Mul(x, t1)
	t1.Square(t2)
	for s := 1; s < 2; s++ {
		t1.Square(t1)
	}
	t1.Mul(z, t1)
	t3.Square(t1)
	for s := 1; s < 4; s++ {
		t3.Square(t3)
	}
	t0.Mul(t0, t3)
	t3.Square(t0)
	for s := 1; s < 11; s++ {
		t3.Square(t3)
	}
	t0.Mul(t0, t3)
	t3.Square(t0)
	for s := 1; s < 5; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	t3.Square(t2)
	for s := 1; s < 27; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	t3.Square(t2)
	for s := 1; s < 54; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	t3.Square(t2)
	for s := 1; s < 108; s++ {
		t3.Square(t3)
	}
	t2.Mul(t2, t3)
	for s := 0; s < 7; s++ {
		t2.Square(t2)
	}
	t1.Mul(t1, t2)
	for s := 0; s < 23; s++ {
		t1.Square(t1)
	}
	t0.Mul(t0, t1)
	for s := 0; s < 6; s++ {
		t0.Square(t0)
	}
	z.Mul(z, t0)
	for s := 0; s < 2; s++ {
		z.Square(z)
	}
}
