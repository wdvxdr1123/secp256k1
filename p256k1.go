// Copyright 2022 The fiat Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secp256k1

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/wdvxdr1123/secp256k1/internal/fiat"
)

var p256k1B, _ = new(fiat.Element).SetBytes([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7})

var p256k1G, _ = NewP256K1Point().SetBytes([]byte{0x4, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0xb, 0x7, 0x2, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0xe, 0x11, 0x8, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8})

var p256k1B3 = new(fiat.Element)

func init() {
	p256k1B3.Add(p256k1B, p256k1B)
	p256k1B3.Add(p256k1B3, p256k1B)
}

// p256k1ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const p256k1ElementLength = 32

// P256K1Point is a P256K1 point. The zero value is NOT valid.
type P256K1Point struct {
	// The point is represented in projective coordinates (X:Y:Z),
	// where x = X/Z and y = Y/Z.
	x, y, z *fiat.Element
}

// NewP256K1Point returns a new P256K1Point representing the point at infinity point.
func NewP256K1Point() *P256K1Point {
	return &P256K1Point{
		x: new(fiat.Element),
		y: new(fiat.Element).One(),
		z: new(fiat.Element),
	}
}

// NewP256K1Generator returns a new P256K1Point set to the canonical generator.
func NewP256K1Generator() *P256K1Point {
	return (&P256K1Point{
		x: new(fiat.Element),
		y: new(fiat.Element),
		z: new(fiat.Element),
	}).Set(p256k1G)
}

// Set sets p = q and returns p.
func (p *P256K1Point) Set(q *P256K1Point) *P256K1Point {
	p.x.Set(q.x)
	p.y.Set(q.y)
	p.z.Set(q.z)
	return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *P256K1Point) SetBytes(b []byte) (_ *P256K1Point, e error) {
	defer func() {
		if e != nil {
			fmt.Printf("%x\n", b)
			fmt.Println(e)
		}
	}()
	switch {
	// Point at infinity.
	case len(b) == 1 && b[0] == 0:
		return p.Set(NewP256K1Point()), nil

	// Uncompressed form.
	case len(b) == 1+2*p256k1ElementLength && b[0] == 4:
		x, err := new(fiat.Element).SetBytes(b[1 : 1+p256k1ElementLength])
		if err != nil {
			return nil, err
		}
		y, err := new(fiat.Element).SetBytes(b[1+p256k1ElementLength:])
		if err != nil {
			return nil, err
		}
		if err := p256k1CheckOnCurve(x, y); err != nil {
			return nil, err
		}
		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil

	// Compressed form.
	case len(b) == 1+p256k1ElementLength && (b[0] == 2 || b[0] == 3):
		x, err := new(fiat.Element).SetBytes(b[1:])
		if err != nil {
			return nil, err
		}

		// y² = x³ + b
		y := p256k1Polynomial(new(fiat.Element), x)
		if !p256k1Sqrt(y, y) {
			return nil, errors.New("invalid P256K1 compressed point encoding")
		}

		// Select the positive or negative root, as indicated by the least
		// significant bit, based on the encoding type byte.
		otherRoot := new(fiat.Element)
		otherRoot.Sub(otherRoot, y)
		cond := y.Bytes()[p256k1ElementLength-1]&1 ^ b[0]&1
		y.Select(otherRoot, y, int(cond))

		p.x.Set(x)
		p.y.Set(y)
		p.z.One()
		return p, nil

	default:
		return nil, errors.New("invalid P256K1 point encoding")
	}
}

// p256k1Polynomial sets y2 to x³ + b, and returns y2.
func p256k1Polynomial(y2, x *fiat.Element) *fiat.Element {
	y2.Square(x)
	y2.Mul(y2, x)

	return y2.Add(y2, p256k1B)
}

func p256k1CheckOnCurve(x, y *fiat.Element) error {
	// y² = x³ + b
	rhs := p256k1Polynomial(new(fiat.Element), x)
	lhs := new(fiat.Element).Square(y)
	if rhs.Equal(lhs) != 1 {
		return errors.New("P256K1 point not on curve")
	}
	return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *P256K1Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + 2*p256k1ElementLength]byte
	return p.bytes(&out)
}

func (p *P256K1Point) bytes(out *[1 + 2*p256k1ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new(fiat.Element).Invert(p.z)
	x := new(fiat.Element).Mul(p.x, zinv)
	y := new(fiat.Element).Mul(p.y, zinv)

	buf := append(out[:0], 4)
	buf = append(buf, x.Bytes()...)
	buf = append(buf, y.Bytes()...)
	return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *P256K1Point) BytesX() ([]byte, error) {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [p256k1ElementLength]byte
	return p.bytesX(&out)
}
func (p *P256K1Point) bytesX(out *[p256k1ElementLength]byte) ([]byte, error) {
	if p.z.IsZero() == 1 {
		return nil, errors.New("P256K1 point is the point at infinity")
	}
	zinv := new(fiat.Element).Invert(p.z)
	x := new(fiat.Element).Mul(p.x, zinv)
	return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *P256K1Point) BytesCompressed() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [1 + p256k1ElementLength]byte
	return p.bytesCompressed(&out)
}

func (p *P256K1Point) bytesCompressed(out *[1 + p256k1ElementLength]byte) []byte {
	if p.z.IsZero() == 1 {
		return append(out[:0], 0)
	}

	zinv := new(fiat.Element).Invert(p.z)
	x := new(fiat.Element).Mul(p.x, zinv)
	y := new(fiat.Element).Mul(p.y, zinv)

	// Encode the sign of the y coordinate (indicated by the least significant
	// bit) as the encoding type (2 or 3).
	buf := append(out[:0], 2)
	buf[0] |= y.Bytes()[p256k1ElementLength-1] & 1
	buf = append(buf, x.Bytes()...)
	return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *P256K1Point) Add(p1, p2 *P256K1Point) *P256K1Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	t0 := new(fiat.Element).Mul(p1.x, p2.x) // t0 := X1 * X2
	t1 := new(fiat.Element).Mul(p1.y, p2.y) // t1 := Y1 * Y2
	t2 := new(fiat.Element).Mul(p1.z, p2.z) // t2 := Z1 * Z2
	t3 := new(fiat.Element).Add(p1.x, p1.y) // t3 := X1 + Y1
	t4 := new(fiat.Element).Add(p2.x, p2.y) // t4 := X2 + Y2
	t3.Mul(t3, t4)                          // t3 := t3 * t4
	t4.Add(t0, t1)                          // t4 := t0 + t1
	t3.Sub(t3, t4)                          // t3 := t3 - t4
	t4.Add(p1.y, p1.z)                      // t4 := Y1 + Z1
	x3 := new(fiat.Element).Add(p2.y, p2.z) // X3 := Y2 + Z2
	t4.Mul(t4, x3)                          // t4 := t4 * X3
	x3.Add(t1, t2)                          // X3 := t1 + t2
	t4.Sub(t4, x3)                          // t4 := t4 - X3
	x3.Add(p1.x, p1.z)                      // X3 := X1 + Z1
	y3 := new(fiat.Element).Add(p2.x, p2.z) // Y3 := X2 + Z2
	x3.Mul(x3, y3)                          // X3 := X3 * Y3
	y3.Add(t0, t2)                          // Y3 := t0 + t2
	y3.Sub(x3, y3)                          // Y3 := X3 - Y3
	x3.Add(t0, t0)                          // X3 := t0 + t0
	t0.Add(x3, t0)                          // t0 := X3 + t0
	t2.Mul(p256k1B3, t2)                    // t2 := b3 * t2
	z3 := new(fiat.Element).Add(t1, t2)     // Z3 := t1 * t2
	t1.Sub(t1, t2)                          // t1 := t1 -t2
	y3.Mul(p256k1B3, y3)                    // Y3 := b3*Y3
	x3.Mul(t4, y3)                          // X3 := t4 * Y3
	t2.Mul(t3, t1)                          // t2 := t3 * t1
	x3.Sub(t2, x3)                          // x3 := t2 - X3
	y3.Mul(y3, t0)                          // Y3 := Y3 * t0
	t1.Mul(t1, z3)                          // t1 := t1 * Z3
	y3.Add(t1, y3)                          // Y3 := t1 + Y3
	t0.Mul(t0, t3)                          // t0 := t0 * t3
	z3.Mul(z3, t4)                          // Z3 := Z3 * t4
	z3.Add(z3, t0)                          // Z3 := Z3 + t0

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Sub sets q = p1 - p2, and returns q. The points may overlap.
func (q *P256K1Point) Sub(p1, p2 *P256K1Point) *P256K1Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	t0 := new(fiat.Element).Mul(p1.x, p2.x) // t0 := X1 * X2
	y2 := new(fiat.Element)                 // Y2
	y2.Sub(y2, p2.y)                        // Y2 :=    - Y2
	t1 := new(fiat.Element).Mul(p1.y, y2)   // t1 := Y1 * Y2
	t2 := new(fiat.Element).Mul(p1.z, p2.z) // t2 := Z1 * Z2
	t3 := new(fiat.Element).Add(p1.x, p1.y) // t3 := X1 + Y1
	t4 := new(fiat.Element).Add(p2.x, y2)   // t4 := X2 + Y2
	t3.Mul(t3, t4)                          // t3 := t3 * t4
	t4.Add(t0, t1)                          // t4 := t0 + t1
	t3.Sub(t3, t4)                          // t3 := t3 - t4
	t4.Add(p1.y, p1.z)                      // t4 := Y1 + Z1
	x3 := new(fiat.Element).Add(y2, p2.z)   // X3 := Y2 + Z2
	t4.Mul(t4, x3)                          // t4 := t4 * X3
	x3.Add(t1, t2)                          // X3 := t1 + t2
	t4.Sub(t4, x3)                          // t4 := t4 - X3
	x3.Add(p1.x, p1.z)                      // X3 := X1 + Z1
	y3 := new(fiat.Element).Add(p2.x, p2.z) // Y3 := X2 + Z2
	x3.Mul(x3, y3)                          // X3 := X3 * Y3
	y3.Add(t0, t2)                          // Y3 := t0 + t2
	y3.Sub(x3, y3)                          // Y3 := X3 - Y3
	x3.Add(t0, t0)                          // X3 := t0 + t0
	t0.Add(x3, t0)                          // t0 := X3 + t0
	t2.Mul(p256k1B3, t2)                    // t2 := b3 * t2
	z3 := new(fiat.Element).Add(t1, t2)     // Z3 := t1 * t2
	t1.Sub(t1, t2)                          // t1 := t1 -t2
	y3.Mul(p256k1B3, y3)                    // Y3 := b3*Y3
	x3.Mul(t4, y3)                          // X3 := t4 * Y3
	t2.Mul(t3, t1)                          // t2 := t3 * t1
	x3.Sub(t2, x3)                          // x3 := t2 - X3
	y3.Mul(y3, t0)                          // Y3 := Y3 * t0
	t1.Mul(t1, z3)                          // t1 := t1 * Z3
	y3.Add(t1, y3)                          // Y3 := t1 + Y3
	t0.Mul(t0, t3)                          // t0 := t0 * t3
	z3.Mul(z3, t4)                          // Z3 := Z3 * t4
	z3.Add(z3, t0)                          // Z3 := Z3 + t0

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *P256K1Point) Double(p *P256K1Point) *P256K1Point {
	// Complete addition formula for a = 0 from "Complete addition formulas for
	// prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.

	t0 := new(fiat.Element).Square(p.y)   // t0 := Y^2
	z3 := new(fiat.Element).Add(t0, t0)   // Z3 := t0 + t0
	z3.Add(z3, z3)                        // Z3 := Z3 + Z3
	z3.Add(z3, z3)                        // Z3 := Z3 + Z3
	t1 := new(fiat.Element).Mul(p.y, p.z) // t1 := Y * Z
	t2 := new(fiat.Element).Square(p.z)   // t2 := Z^2
	t2.Mul(p256k1B3, t2)                  // t2 := b3 * t2
	x3 := new(fiat.Element).Mul(t2, z3)   // X3 := t2 * Z3
	y3 := new(fiat.Element).Add(t0, t2)   // Y3 := t0 + t2
	z3.Mul(t1, z3)
	t1.Add(t2, t2)
	t2.Add(t1, t2)

	t0.Sub(t0, t2)
	y3.Mul(t0, y3)
	y3.Add(x3, y3)

	t1.Mul(p.x, p.y)
	x3.Mul(t0, t1)
	x3.Add(x3, x3)

	q.x.Set(x3)
	q.y.Set(y3)
	q.z.Set(z3)
	return q
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *P256K1Point) Select(p1, p2 *P256K1Point, cond int) *P256K1Point {
	q.x.Select(p1.x, p2.x, cond)
	q.y.Select(p1.y, p2.y, cond)
	q.z.Select(p1.z, p2.z, cond)
	return q
}

// A p256k1Table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type p256k1Table [15]*P256K1Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *p256k1Table) Select(p *P256K1Point, n uint8) {
	if n >= 16 {
		panic("nistec: internal error: p256k1Table called with out-of-bounds value")
	}
	p.Set(NewP256K1Point())
	for i := uint8(1); i < 16; i++ {
		cond := subtle.ConstantTimeByteEq(i, n)
		p.Select(table[i-1], p, cond)
	}
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *P256K1Point) ScalarMult(q *P256K1Point, scalar []byte) (*P256K1Point, error) {
	// Compute a p256k1Table for the base point q. The explicit NewP256K1Point
	// calls get inlined, letting the allocations live on the stack.
	var table = p256k1Table{NewP256K1Point(), NewP256K1Point(), NewP256K1Point(),
		NewP256K1Point(), NewP256K1Point(), NewP256K1Point(), NewP256K1Point(),
		NewP256K1Point(), NewP256K1Point(), NewP256K1Point(), NewP256K1Point(),
		NewP256K1Point(), NewP256K1Point(), NewP256K1Point(), NewP256K1Point()}
	table[0].Set(q)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], q)
	}

	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := NewP256K1Point()
	p.Set(NewP256K1Point())
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

var p256k1GeneratorTable *[p256k1ElementLength * 2]p256k1Table
var p256k1GeneratorTableOnce sync.Once

// generatorTable returns a sequence of p256k1Tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *P256K1Point) generatorTable() *[p256k1ElementLength * 2]p256k1Table {
	p256k1GeneratorTableOnce.Do(func() {
		p256k1GeneratorTable = new([p256k1ElementLength * 2]p256k1Table)
		base := NewP256K1Generator()
		for i := 0; i < p256k1ElementLength*2; i++ {
			p256k1GeneratorTable[i][0] = NewP256K1Point().Set(base)
			for j := 1; j < 15; j++ {
				p256k1GeneratorTable[i][j] = NewP256K1Point().Add(p256k1GeneratorTable[i][j-1], base)
			}
			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return p256k1GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *P256K1Point) ScalarBaseMult(scalar []byte) (*P256K1Point, error) {
	if len(scalar) != p256k1ElementLength {
		return nil, errors.New("invalid scalar length")
	}
	tables := p.generatorTable()

	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := NewP256K1Point()
	p.Set(NewP256K1Point())
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

// p256k1Sqrt sets e to a square root of x. If x is not a square, p256k1Sqrt returns
// false and e is unchanged. e and x can overlap.
func p256k1Sqrt(e, x *fiat.Element) (isSquare bool) {
	candidate := new(fiat.Element)
	p256k1SqrtCandidate(candidate, x)
	square := new(fiat.Element).Square(candidate)
	if square.Equal(x) != 1 {
		return false
	}
	e.Set(candidate)
	return true
}

// p256k1SqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func p256k1SqrtCandidate(z, x *fiat.Element) {
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
	var t0 = new(fiat.Element)
	var t1 = new(fiat.Element)
	var t2 = new(fiat.Element)
	var t3 = new(fiat.Element)

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
