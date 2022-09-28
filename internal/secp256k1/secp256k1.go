package secp256k1

import (
	"crypto/subtle"
	"errors"
	"math/bits"
)

// Element is an integer modulo 2^256 - 2^32 - 977.
//
// The zero value is a valid zero element.
type Element [4]uint64

const ElementLen = 32

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
	zero := make([]byte, ElementLen)
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
	var out [ElementLen]byte
	return e.bytes(&out)
}

func (e *Element) bytes(out *[ElementLen]byte) []byte {
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
	if len(v) != ElementLen {
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

	var in [ElementLen]byte
	copy(in[:], v)
	invertEndianness(in[:])
	var tmp Element
	fromBytes(&tmp, &in)
	toMontgomery(e, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *Element) Add(t1, t2 *Element) *Element {
	x1, x2 := bits.Add64(t1[0], t2[0], 0)
	x3, x4 := bits.Add64(t1[1], t2[1], x2)
	x5, x6 := bits.Add64(t1[2], t2[2], x4)
	x7, x8 := bits.Add64(t1[3], t2[3], x6)
	x9, x10 := bits.Sub64(x1, 0xfffffffefffffc2f, 0)
	x11, x12 := bits.Sub64(x3, 0xffffffffffffffff, x10)
	x13, x14 := bits.Sub64(x5, 0xffffffffffffffff, x12)
	x15, x16 := bits.Sub64(x7, 0xffffffffffffffff, x14)
	_, x18 := bits.Sub64(x8, 0, x16)
	x19 := cmovznz(x18, x9, x1)
	x20 := cmovznz(x18, x11, x3)
	x21 := cmovznz(x18, x13, x5)
	x22 := cmovznz(x18, x15, x7)
	e[0] = x19
	e[1] = x20
	e[2] = x21
	e[3] = x22
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *Element) Sub(t1, t2 *Element) *Element {
	x1, x2 := bits.Sub64(t1[0], t2[0], 0)
	x3, x4 := bits.Sub64(t1[1], t2[1], x2)
	x5, x6 := bits.Sub64(t1[2], t2[2], x4)
	x7, x8 := bits.Sub64(t1[3], t2[3], x6)
	x9 := cmovznz(x8, 0, 0xffffffffffffffff)
	x10, x11 := bits.Add64(x1, x9&0xfffffffefffffc2f, 0)
	x12, x13 := bits.Add64(x3, x9, x11)
	x14, x15 := bits.Add64(x5, x9, x13)
	x16, _ := bits.Add64(x7, x9, x15)
	e[0] = x10
	e[1] = x12
	e[2] = x14
	e[3] = x16
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *Element) Mul(t1, t2 *Element) *Element {
	x1 := t1[1]
	x2 := t1[2]
	x3 := t1[3]
	x4 := t1[0]
	x6, x5 := bits.Mul64(x4, t2[3])
	x8, x7 := bits.Mul64(x4, t2[2])
	x10, x9 := bits.Mul64(x4, t2[1])
	x12, x11 := bits.Mul64(x4, t2[0])
	x13, x14 := bits.Add64(x12, x9, 0)
	x15, x16 := bits.Add64(x10, x7, x14)
	x17, x18 := bits.Add64(x8, x5, x16)
	x19 := x18 + x6
	_, x20 := bits.Mul64(x11, 0xd838091dd2253531)
	x23, x22 := bits.Mul64(x20, 0xffffffffffffffff)
	x25, x24 := bits.Mul64(x20, 0xffffffffffffffff)
	x27, x26 := bits.Mul64(x20, 0xffffffffffffffff)
	x29, x28 := bits.Mul64(x20, 0xfffffffefffffc2f)
	x30, x31 := bits.Add64(x29, x26, 0)
	x32, x33 := bits.Add64(x27, x24, x31)
	x34, x35 := bits.Add64(x25, x22, x33)
	x36 := x35 + x23
	_, x38 := bits.Add64(x11, x28, 0)
	x39, x40 := bits.Add64(x13, x30, x38)
	x41, x42 := bits.Add64(x15, x32, x40)
	x43, x44 := bits.Add64(x17, x34, x42)
	x45, x46 := bits.Add64(x19, x36, x44)
	x48, x47 := bits.Mul64(x1, t2[3])
	x50, x49 := bits.Mul64(x1, t2[2])
	x52, x51 := bits.Mul64(x1, t2[1])
	x54, x53 := bits.Mul64(x1, t2[0])
	x55, x56 := bits.Add64(x54, x51, 0)
	x57, x58 := bits.Add64(x52, x49, x56)
	x59, x60 := bits.Add64(x50, x47, x58)
	x61 := x60 + x48
	x62, x63 := bits.Add64(x39, x53, 0)
	x64, x65 := bits.Add64(x41, x55, x63)
	x66, x67 := bits.Add64(x43, x57, x65)
	x68, x69 := bits.Add64(x45, x59, x67)
	x70, x71 := bits.Add64(x46, x61, x69)
	_, x72 := bits.Mul64(x62, 0xd838091dd2253531)
	x75, x74 := bits.Mul64(x72, 0xffffffffffffffff)
	x77, x76 := bits.Mul64(x72, 0xffffffffffffffff)
	x79, x78 := bits.Mul64(x72, 0xffffffffffffffff)
	x81, x80 := bits.Mul64(x72, 0xfffffffefffffc2f)
	x82, x83 := bits.Add64(x81, x78, 0)
	x84, x85 := bits.Add64(x79, x76, x83)
	x86, x87 := bits.Add64(x77, x74, x85)
	x88 := x87 + x75
	_, x90 := bits.Add64(x62, x80, 0)
	x91, x92 := bits.Add64(x64, x82, x90)
	x93, x94 := bits.Add64(x66, x84, x92)
	x95, x96 := bits.Add64(x68, x86, x94)
	x97, x98 := bits.Add64(x70, x88, x96)
	x99 := x98 + x71
	x101, x100 := bits.Mul64(x2, t2[3])
	x103, x102 := bits.Mul64(x2, t2[2])
	x105, x104 := bits.Mul64(x2, t2[1])
	x107, x106 := bits.Mul64(x2, t2[0])
	x108, x109 := bits.Add64(x107, x104, 0)
	x110, x111 := bits.Add64(x105, x102, x109)
	x112, x113 := bits.Add64(x103, x100, x111)
	x114 := x113 + x101
	x115, x116 := bits.Add64(x91, x106, 0)
	x117, x118 := bits.Add64(x93, x108, x116)
	x119, x120 := bits.Add64(x95, x110, x118)
	x121, x122 := bits.Add64(x97, x112, x120)
	x123, x124 := bits.Add64(x99, x114, x122)
	_, x125 := bits.Mul64(x115, 0xd838091dd2253531)
	x128, x127 := bits.Mul64(x125, 0xffffffffffffffff)
	x130, x129 := bits.Mul64(x125, 0xffffffffffffffff)
	x132, x131 := bits.Mul64(x125, 0xffffffffffffffff)
	x134, x133 := bits.Mul64(x125, 0xfffffffefffffc2f)
	x135, x136 := bits.Add64(x134, x131, 0)
	x137, x138 := bits.Add64(x132, x129, x136)
	x139, x140 := bits.Add64(x130, x127, x138)
	x141 := x140 + x128
	_, x143 := bits.Add64(x115, x133, 0)
	x144, x145 := bits.Add64(x117, x135, x143)
	x146, x147 := bits.Add64(x119, x137, x145)
	x148, x149 := bits.Add64(x121, x139, x147)
	x150, x151 := bits.Add64(x123, x141, x149)
	x152 := x151 + x124
	x154, x153 := bits.Mul64(x3, t2[3])
	x156, x155 := bits.Mul64(x3, t2[2])
	x158, x157 := bits.Mul64(x3, t2[1])
	x160, x159 := bits.Mul64(x3, t2[0])
	x161, x162 := bits.Add64(x160, x157, 0)
	x163, x164 := bits.Add64(x158, x155, x162)
	x165, x166 := bits.Add64(x156, x153, x164)
	x167 := x166 + x154
	x168, x169 := bits.Add64(x144, x159, 0)
	x170, x171 := bits.Add64(x146, x161, x169)
	x172, x173 := bits.Add64(x148, x163, x171)
	x174, x175 := bits.Add64(x150, x165, x173)
	x176, x177 := bits.Add64(x152, x167, x175)
	_, x178 := bits.Mul64(x168, 0xd838091dd2253531)
	x181, x180 := bits.Mul64(x178, 0xffffffffffffffff)
	x183, x182 := bits.Mul64(x178, 0xffffffffffffffff)
	x185, x184 := bits.Mul64(x178, 0xffffffffffffffff)
	x187, x186 := bits.Mul64(x178, 0xfffffffefffffc2f)
	x188, x189 := bits.Add64(x187, x184, 0)
	x190, x191 := bits.Add64(x185, x182, x189)
	x192, x193 := bits.Add64(x183, x180, x191)
	x194 := x193 + x181
	_, x196 := bits.Add64(x168, x186, 0)
	x197, x198 := bits.Add64(x170, x188, x196)
	x199, x200 := bits.Add64(x172, x190, x198)
	x201, x202 := bits.Add64(x174, x192, x200)
	x203, x204 := bits.Add64(x176, x194, x202)
	x205 := x204 + x177
	x206, x207 := bits.Sub64(x197, 0xfffffffefffffc2f, 0)
	x208, x209 := bits.Sub64(x199, 0xffffffffffffffff, x207)
	x210, x211 := bits.Sub64(x201, 0xffffffffffffffff, x209)
	x212, x213 := bits.Sub64(x203, 0xffffffffffffffff, x211)
	_, x215 := bits.Sub64(x205, 0, x213)
	x216 := cmovznz(x215, x206, x197)
	x217 := cmovznz(x215, x208, x199)
	x218 := cmovznz(x215, x210, x201)
	x219 := cmovznz(x215, x212, x203)
	e[0] = x216
	e[1] = x217
	e[2] = x218
	e[3] = x219
	return e
}

// Square sets e = t * t, and returns e.
func (e *Element) Square(t *Element) *Element {
	x1 := t[1]
	x2 := t[2]
	x3 := t[3]
	x4 := t[0]
	x6, x5 := bits.Mul64(x4, t[3])
	x8, x7 := bits.Mul64(x4, t[2])
	x10, x9 := bits.Mul64(x4, t[1])
	x12, x11 := bits.Mul64(x4, t[0])
	x13, x14 := bits.Add64(x12, x9, 0)
	x15, x16 := bits.Add64(x10, x7, x14)
	x17, x18 := bits.Add64(x8, x5, x16)
	x19 := x18 + x6
	_, x20 := bits.Mul64(x11, 0xd838091dd2253531)
	x23, x22 := bits.Mul64(x20, 0xffffffffffffffff)
	x25, x24 := bits.Mul64(x20, 0xffffffffffffffff)
	x27, x26 := bits.Mul64(x20, 0xffffffffffffffff)
	x29, x28 := bits.Mul64(x20, 0xfffffffefffffc2f)
	x30, x31 := bits.Add64(x29, x26, 0)
	x32, x33 := bits.Add64(x27, x24, x31)
	x34, x35 := bits.Add64(x25, x22, x33)
	x36 := x35 + x23
	_, x38 := bits.Add64(x11, x28, 0)
	x39, x40 := bits.Add64(x13, x30, x38)
	x41, x42 := bits.Add64(x15, x32, x40)
	x43, x44 := bits.Add64(x17, x34, x42)
	x45, x46 := bits.Add64(x19, x36, x44)
	x48, x47 := bits.Mul64(x1, t[3])
	x50, x49 := bits.Mul64(x1, t[2])
	x52, x51 := bits.Mul64(x1, t[1])
	x54, x53 := bits.Mul64(x1, t[0])
	x55, x56 := bits.Add64(x54, x51, 0)
	x57, x58 := bits.Add64(x52, x49, x56)
	x59, x60 := bits.Add64(x50, x47, x58)
	x61 := x60 + x48
	x62, x63 := bits.Add64(x39, x53, 0)
	x64, x65 := bits.Add64(x41, x55, x63)
	x66, x67 := bits.Add64(x43, x57, x65)
	x68, x69 := bits.Add64(x45, x59, x67)
	x70, x71 := bits.Add64(x46, x61, x69)
	_, x72 := bits.Mul64(x62, 0xd838091dd2253531)
	x75, x74 := bits.Mul64(x72, 0xffffffffffffffff)
	x77, x76 := bits.Mul64(x72, 0xffffffffffffffff)
	x79, x78 := bits.Mul64(x72, 0xffffffffffffffff)
	x81, x80 := bits.Mul64(x72, 0xfffffffefffffc2f)
	x82, x83 := bits.Add64(x81, x78, 0)
	x84, x85 := bits.Add64(x79, x76, x83)
	x86, x87 := bits.Add64(x77, x74, x85)
	x88 := x87 + x75
	_, x90 := bits.Add64(x62, x80, 0)
	x91, x92 := bits.Add64(x64, x82, x90)
	x93, x94 := bits.Add64(x66, x84, x92)
	x95, x96 := bits.Add64(x68, x86, x94)
	x97, x98 := bits.Add64(x70, x88, x96)
	x99 := x98 + x71
	x101, x100 := bits.Mul64(x2, t[3])
	x103, x102 := bits.Mul64(x2, t[2])
	x105, x104 := bits.Mul64(x2, t[1])
	x107, x106 := bits.Mul64(x2, t[0])
	x108, x109 := bits.Add64(x107, x104, 0)
	x110, x111 := bits.Add64(x105, x102, x109)
	x112, x113 := bits.Add64(x103, x100, x111)
	x114 := x113 + x101
	x115, x116 := bits.Add64(x91, x106, 0)
	x117, x118 := bits.Add64(x93, x108, x116)
	x119, x120 := bits.Add64(x95, x110, x118)
	x121, x122 := bits.Add64(x97, x112, x120)
	x123, x124 := bits.Add64(x99, x114, x122)
	_, x125 := bits.Mul64(x115, 0xd838091dd2253531)
	x128, x127 := bits.Mul64(x125, 0xffffffffffffffff)
	x130, x129 := bits.Mul64(x125, 0xffffffffffffffff)
	x132, x131 := bits.Mul64(x125, 0xffffffffffffffff)
	x134, x133 := bits.Mul64(x125, 0xfffffffefffffc2f)
	x135, x136 := bits.Add64(x134, x131, 0)
	x137, x138 := bits.Add64(x132, x129, x136)
	x139, x140 := bits.Add64(x130, x127, x138)
	x141 := x140 + x128
	_, x143 := bits.Add64(x115, x133, 0)
	x144, x145 := bits.Add64(x117, x135, x143)
	x146, x147 := bits.Add64(x119, x137, x145)
	x148, x149 := bits.Add64(x121, x139, x147)
	x150, x151 := bits.Add64(x123, x141, x149)
	x152 := x151 + x124
	x154, x153 := bits.Mul64(x3, t[3])
	x156, x155 := bits.Mul64(x3, t[2])
	x158, x157 := bits.Mul64(x3, t[1])
	x160, x159 := bits.Mul64(x3, t[0])
	x161, x162 := bits.Add64(x160, x157, 0)
	x163, x164 := bits.Add64(x158, x155, x162)
	x165, x166 := bits.Add64(x156, x153, x164)
	x167 := x166 + x154
	x168, x169 := bits.Add64(x144, x159, 0)
	x170, x171 := bits.Add64(x146, x161, x169)
	x172, x173 := bits.Add64(x148, x163, x171)
	x174, x175 := bits.Add64(x150, x165, x173)
	x176, x177 := bits.Add64(x152, x167, x175)
	_, x178 := bits.Mul64(x168, 0xd838091dd2253531)
	x181, x180 := bits.Mul64(x178, 0xffffffffffffffff)
	x183, x182 := bits.Mul64(x178, 0xffffffffffffffff)
	x185, x184 := bits.Mul64(x178, 0xffffffffffffffff)
	x187, x186 := bits.Mul64(x178, 0xfffffffefffffc2f)
	x188, x189 := bits.Add64(x187, x184, 0)
	x190, x191 := bits.Add64(x185, x182, x189)
	x192, x193 := bits.Add64(x183, x180, x191)
	x194 := x193 + x181
	_, x196 := bits.Add64(x168, x186, 0)
	x197, x198 := bits.Add64(x170, x188, x196)
	x199, x200 := bits.Add64(x172, x190, x198)
	x201, x202 := bits.Add64(x174, x192, x200)
	x203, x204 := bits.Add64(x176, x194, x202)
	x205 := x204 + x177
	x206, x207 := bits.Sub64(x197, 0xfffffffefffffc2f, 0)
	x208, x209 := bits.Sub64(x199, 0xffffffffffffffff, x207)
	x210, x211 := bits.Sub64(x201, 0xffffffffffffffff, x209)
	x212, x213 := bits.Sub64(x203, 0xffffffffffffffff, x211)
	_, x215 := bits.Sub64(x205, 0, x213)
	x216 := cmovznz(x215, x206, x197)
	x217 := cmovznz(x215, x208, x199)
	x218 := cmovznz(x215, x210, x201)
	x219 := cmovznz(x215, x212, x203)
	e[0] = x216
	e[1] = x217
	e[2] = x218
	e[3] = x219
	return e
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
