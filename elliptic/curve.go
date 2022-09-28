// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elliptic

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"sync"

	"github.com/wdvxdr1123/secp256k1"
)

type s256Curve struct {
	nistCurve[*secp.P256K1Point]
}

var s256 = &s256Curve{nistCurve[*secp.P256K1Point]{
	newPoint: secp.NewP256K1Point,
}}

var s256Once sync.Once

func S256() elliptic.Curve {
	s256Once.Do(initS256)
	return s256
}

func initS256() {
	s256.params = &elliptic.CurveParams{
		Name:    "P-256",
		BitSize: 256,
		// FIPS 186-4, section D.1.2.3
		P:  bigFromDecimal("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
		N:  bigFromDecimal("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
		B:  bigFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
		Gx: bigFromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		Gy: bigFromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
	}
}

// nistCurve is a Curve implementation based on a nistec Point.
//
// It's a wrapper that exposes the big.Int-based Curve interface and encodes the
// legacy idiosyncrasies it requires, such as invalid and infinity point
// handling.
//
// To interact with the nistec package, points are encoded into and decoded from
// properly formatted byte slices. All big.Int use is limited to this package.
// Encoding and decoding is 1/1000th of the runtime of a scalar multiplication,
// so the overhead is acceptable.
type nistCurve[Point nistPoint[Point]] struct {
	newPoint func() Point
	params   *elliptic.CurveParams
}

// nistPoint is a generic constraint for the nistec Point types.
type nistPoint[T any] interface {
	Bytes() []byte
	SetBytes([]byte) (T, error)
	Add(T, T) T
	Double(T) T
	ScalarMult(T, []byte) (T, error)
	ScalarBaseMult([]byte) (T, error)
}

func (curve *nistCurve[Point]) Params() *elliptic.CurveParams {
	return curve.params
}

func (curve *nistCurve[Point]) IsOnCurve(x, y *big.Int) bool {
	// IsOnCurve is documented to reject (0, 0), the conventional point at
	// infinity, which however is accepted by pointFromAffine.
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, err := curve.pointFromAffine(x, y)
	return err == nil
}

func (curve *nistCurve[Point]) pointFromAffine(x, y *big.Int) (p Point, err error) {
	p = curve.newPoint()
	// (0, 0) is by convention the point at infinity, which can't be represented
	// in affine coordinates. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return p, nil
	}
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > curve.params.BitSize || y.BitLen() > curve.params.BitSize {
		return p, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (curve.params.BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return p.SetBytes(buf)
}

func (curve *nistCurve[Point]) pointToAffine(p Point) (x, y *big.Int) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity, which the affine
		// coordinates API represents as (0, 0) by convention.
		return new(big.Int), new(big.Int)
	}
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y
}

func (curve *nistCurve[Point]) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("crypto/elliptic: Add was called on an invalid point")
	}
	p2, err := curve.pointFromAffine(x2, y2)
	if err != nil {
		panic("crypto/elliptic: Add was called on an invalid point")
	}
	return curve.pointToAffine(p1.Add(p1, p2))
}

func (curve *nistCurve[Point]) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(x1, y1)
	if err != nil {
		panic("crypto/elliptic: Double was called on an invalid point")
	}
	return curve.pointToAffine(p.Double(p))
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the nistec scalar multiplication functions.
func (curve *nistCurve[Point]) normalizeScalar(scalar []byte) []byte {
	byteSize := (curve.params.N.BitLen() + 7) / 8
	if len(scalar) == byteSize {
		return scalar
	}
	s := new(big.Int).SetBytes(scalar)
	if len(scalar) > byteSize {
		s.Mod(s, curve.params.N)
	}
	out := make([]byte, byteSize)
	return s.FillBytes(out)
}

func (curve *nistCurve[Point]) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	p, err := curve.pointFromAffine(Bx, By)
	if err != nil {
		panic("crypto/elliptic: ScalarMult was called on an invalid point")
	}
	scalar = curve.normalizeScalar(scalar)
	p, err = p.ScalarMult(p, scalar)
	if err != nil {
		panic("crypto/elliptic: nistec rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

func (curve *nistCurve[Point]) ScalarBaseMult(scalar []byte) (*big.Int, *big.Int) {
	scalar = curve.normalizeScalar(scalar)
	p, err := curve.newPoint().ScalarBaseMult(scalar)
	if err != nil {
		panic("crypto/elliptic: nistec rejected normalized scalar")
	}
	return curve.pointToAffine(p)
}

// CombinedMult returns [s1]G + [s2]P where G is the generator. It's used
// through an interface upgrade in crypto/ecdsa.
func (curve *nistCurve[Point]) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
	s1 = curve.normalizeScalar(s1)
	q, err := curve.newPoint().ScalarBaseMult(s1)
	if err != nil {
		panic("crypto/elliptic: nistec rejected normalized scalar")
	}
	p, err := curve.pointFromAffine(Px, Py)
	if err != nil {
		panic("crypto/elliptic: CombinedMult was called on an invalid point")
	}
	s2 = curve.normalizeScalar(s2)
	p, err = p.ScalarMult(p, s2)
	if err != nil {
		panic("crypto/elliptic: nistec rejected normalized scalar")
	}
	return curve.pointToAffine(p.Add(p, q))
}

func (curve *nistCurve[Point]) Unmarshal(data []byte) (x, y *big.Int) {
	if len(data) == 0 || data[0] != 4 {
		return nil, nil
	}
	// Use SetBytes to check that data encodes a valid point.
	_, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	// We don't use pointToAffine because it involves an expensive field
	// inversion to convert from Jacobian to affine coordinates, which we
	// already have.
	byteLen := (curve.params.BitSize + 7) / 8
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return x, y
}

func (curve *nistCurve[Point]) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	if len(data) == 0 || (data[0] != 2 && data[0] != 3) {
		return nil, nil
	}
	p, err := curve.newPoint().SetBytes(data)
	if err != nil {
		return nil, nil
	}
	return curve.pointToAffine(p)
}

func bigFromDecimal(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("crypto/elliptic: internal error: invalid encoding")
	}
	return b
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("crypto/elliptic: internal error: invalid encoding")
	}
	return b
}
