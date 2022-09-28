// Copyright 2022 The secp256k1 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package secp256k1

import "math/bits"

// cmovznz is a single-word conditional move.
//
// Postconditions:
//
//	out1 = (if arg1 = 0 then arg2 else arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [0x0 ~> 0xffffffffffffffff]
//	arg3: [0x0 ~> 0xffffffffffffffff]
//
// Output Bounds:
//
//	out1: [0x0 ~> 0xffffffffffffffff]
func cmovznz(arg1 uint64, arg2 uint64, arg3 uint64) uint64 {
	x1 := arg1 * 0xffffffffffffffff
	return (x1 & arg3) | ((^x1) & arg2)
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

// fromMontgomery translates a field element out of the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = (eval arg1 * ((2^64)⁻¹ mod m)^4) mod m
//	0 ≤ eval out1 < m
func fromMontgomery(out1 *Element, arg1 *Element) {
	x1 := arg1[0]
	_, x2 := bits.Mul64(x1, 0xd838091dd2253531)
	x5, x4 := bits.Mul64(x2, 0xffffffffffffffff)
	x7, x6 := bits.Mul64(x2, 0xffffffffffffffff)
	x9, x8 := bits.Mul64(x2, 0xffffffffffffffff)
	x11, x10 := bits.Mul64(x2, 0xfffffffefffffc2f)
	x12, x13 := bits.Add64(x11, x8, 0)
	x14, x15 := bits.Add64(x9, x6, x13)
	x16, x17 := bits.Add64(x7, x4, x15)
	_, x19 := bits.Add64(x1, x10, 0)
	x20, x21 := bits.Add64(0, x12, x19)
	x22, x23 := bits.Add64(0, x14, x21)
	x24, x25 := bits.Add64(0, x16, x23)
	x26, x27 := bits.Add64(0, x17+x5, x25)
	x28, x29 := bits.Add64(x20, arg1[1], 0)
	x30, x31 := bits.Add64(x22, 0, x29)
	x32, x33 := bits.Add64(x24, 0, x31)
	x34, x35 := bits.Add64(x26, 0, x33)
	_, x36 := bits.Mul64(x28, 0xd838091dd2253531)
	x39, x38 := bits.Mul64(x36, 0xffffffffffffffff)
	x41, x40 := bits.Mul64(x36, 0xffffffffffffffff)
	x43, x42 := bits.Mul64(x36, 0xffffffffffffffff)
	x45, x44 := bits.Mul64(x36, 0xfffffffefffffc2f)
	x46, x47 := bits.Add64(x45, x42, 0)
	x48, x49 := bits.Add64(x43, x40, x47)
	x50, x51 := bits.Add64(x41, x38, x49)
	_, x53 := bits.Add64(x28, x44, 0)
	x54, x55 := bits.Add64(x30, x46, x53)
	x56, x57 := bits.Add64(x32, x48, x55)
	x58, x59 := bits.Add64(x34, x50, x57)
	x60, x61 := bits.Add64(x35+x27, x51+x39, x59)
	x62, x63 := bits.Add64(x54, arg1[2], 0)
	x64, x65 := bits.Add64(x56, 0, x63)
	x66, x67 := bits.Add64(x58, 0, x65)
	x68, x69 := bits.Add64(x60, 0, x67)
	_, x70 := bits.Mul64(x62, 0xd838091dd2253531)
	x73, x72 := bits.Mul64(x70, 0xffffffffffffffff)
	x75, x74 := bits.Mul64(x70, 0xffffffffffffffff)
	x77, x76 := bits.Mul64(x70, 0xffffffffffffffff)
	x79, x78 := bits.Mul64(x70, 0xfffffffefffffc2f)
	x80, x81 := bits.Add64(x79, x76, 0)
	x82, x83 := bits.Add64(x77, x74, x81)
	x84, x85 := bits.Add64(x75, x72, x83)
	_, x87 := bits.Add64(x62, x78, 0)
	x88, x89 := bits.Add64(x64, x80, x87)
	x90, x91 := bits.Add64(x66, x82, x89)
	x92, x93 := bits.Add64(x68, x84, x91)
	x94, x95 := bits.Add64(x69+x61, x85+x73, x93)
	x96, x97 := bits.Add64(x88, arg1[3], 0)
	x98, x99 := bits.Add64(x90, 0, x97)
	x100, x101 := bits.Add64(x92, 0, x99)
	x102, x103 := bits.Add64(x94, 0, x101)
	_, x104 := bits.Mul64(x96, 0xd838091dd2253531)
	x107, x106 := bits.Mul64(x104, 0xffffffffffffffff)
	x109, x108 := bits.Mul64(x104, 0xffffffffffffffff)
	x111, x110 := bits.Mul64(x104, 0xffffffffffffffff)
	x113, x112 := bits.Mul64(x104, 0xfffffffefffffc2f)
	x114, x115 := bits.Add64(x113, x110, 0)
	x116, x117 := bits.Add64(x111, x108, x115)
	x118, x119 := bits.Add64(x109, x106, x117)
	_, x121 := bits.Add64(x96, x112, 0)
	x122, x123 := bits.Add64(x98, x114, x121)
	x124, x125 := bits.Add64(x100, x116, x123)
	x126, x127 := bits.Add64(x102, x118, x125)
	x128, x129 := bits.Add64(x103+x95, x119+x107, x127)
	x130, x131 := bits.Sub64(x122, 0xfffffffefffffc2f, 0)
	x132, x133 := bits.Sub64(x124, 0xffffffffffffffff, x131)
	x134, x135 := bits.Sub64(x126, 0xffffffffffffffff, x133)
	x136, x137 := bits.Sub64(x128, 0xffffffffffffffff, x135)
	_, x139 := bits.Sub64(x129, 0, x137)
	out1[0] = cmovznz(x139, x130, x122)
	out1[1] = cmovznz(x139, x132, x124)
	out1[2] = cmovznz(x139, x134, x126)
	out1[3] = cmovznz(x139, x136, x128)
}

// toMontgomery translates a field element into the Montgomery domain.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	eval (from_montgomery out1) mod m = eval arg1 mod m
//	0 ≤ eval out1 < m
func toMontgomery(out1 *Element, arg1 *Element) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	x6, x5 := bits.Mul64(x4, 0x7a2000e90a1)
	x7, x8 := bits.Add64(x6, x4, 0)
	_, x9 := bits.Mul64(x5, 0xd838091dd2253531)
	x12, x11 := bits.Mul64(x9, 0xffffffffffffffff)
	x14, x13 := bits.Mul64(x9, 0xffffffffffffffff)
	x16, x15 := bits.Mul64(x9, 0xffffffffffffffff)
	x18, x17 := bits.Mul64(x9, 0xfffffffefffffc2f)
	x19, x20 := bits.Add64(x18, x15, 0)
	x21, x22 := bits.Add64(x16, x13, x20)
	x23, x24 := bits.Add64(x14, x11, x22)
	_, x26 := bits.Add64(x5, x17, 0)
	x27, x28 := bits.Add64(x7, x19, x26)
	x29, x30 := bits.Add64(x8, x21, x28)
	x31, x32 := bits.Add64(0, x23, x30)
	x33, x34 := bits.Add64(0, x24+x12, x32)
	x36, x35 := bits.Mul64(x1, 0x7a2000e90a1)
	x37, x38 := bits.Add64(x36, x1, 0)
	x39, x40 := bits.Add64(x27, x35, 0)
	x41, x42 := bits.Add64(x29, x37, x40)
	x43, x44 := bits.Add64(x31, x38, x42)
	x45, x46 := bits.Add64(x33, 0, x44)
	_, x47 := bits.Mul64(x39, 0xd838091dd2253531)
	x50, x49 := bits.Mul64(x47, 0xffffffffffffffff)
	x52, x51 := bits.Mul64(x47, 0xffffffffffffffff)
	x54, x53 := bits.Mul64(x47, 0xffffffffffffffff)
	x56, x55 := bits.Mul64(x47, 0xfffffffefffffc2f)
	x57, x58 := bits.Add64(x56, x53, 0)
	x59, x60 := bits.Add64(x54, x51, x58)
	x61, x62 := bits.Add64(x52, x49, x60)
	_, x64 := bits.Add64(x39, x55, 0)
	x65, x66 := bits.Add64(x41, x57, x64)
	x67, x68 := bits.Add64(x43, x59, x66)
	x69, x70 := bits.Add64(x45, x61, x68)
	x71, x72 := bits.Add64(x46+x34, x62+x50, x70)
	x74, x73 := bits.Mul64(x2, 0x7a2000e90a1)
	x75, x76 := bits.Add64(x74, x2, 0)
	x77, x78 := bits.Add64(x65, x73, 0)
	x79, x80 := bits.Add64(x67, x75, x78)
	x81, x82 := bits.Add64(x69, x76, x80)
	x83, x84 := bits.Add64(x71, 0, x82)
	_, x85 := bits.Mul64(x77, 0xd838091dd2253531)
	x88, x87 := bits.Mul64(x85, 0xffffffffffffffff)
	x90, x89 := bits.Mul64(x85, 0xffffffffffffffff)
	x92, x91 := bits.Mul64(x85, 0xffffffffffffffff)
	x94, x93 := bits.Mul64(x85, 0xfffffffefffffc2f)
	x95, x96 := bits.Add64(x94, x91, 0)
	x97, x98 := bits.Add64(x92, x89, x96)
	x99, x100 := bits.Add64(x90, x87, x98)
	_, x102 := bits.Add64(x77, x93, 0)
	x103, x104 := bits.Add64(x79, x95, x102)
	x105, x106 := bits.Add64(x81, x97, x104)
	x107, x108 := bits.Add64(x83, x99, x106)
	x109, x110 := bits.Add64(x84+x72, x100+x88, x108)
	x112, x111 := bits.Mul64(x3, 0x7a2000e90a1)
	x113, x114 := bits.Add64(x112, x3, 0)
	x115, x116 := bits.Add64(x103, x111, 0)
	x117, x118 := bits.Add64(x105, x113, x116)
	x119, x120 := bits.Add64(x107, x114, x118)
	x121, x122 := bits.Add64(x109, 0, x120)
	_, x123 := bits.Mul64(x115, 0xd838091dd2253531)
	x126, x125 := bits.Mul64(x123, 0xffffffffffffffff)
	x128, x127 := bits.Mul64(x123, 0xffffffffffffffff)
	x130, x129 := bits.Mul64(x123, 0xffffffffffffffff)
	x132, x131 := bits.Mul64(x123, 0xfffffffefffffc2f)
	x133, x134 := bits.Add64(x132, x129, 0)
	x135, x136 := bits.Add64(x130, x127, x134)
	x137, x138 := bits.Add64(x128, x125, x136)
	_, x140 := bits.Add64(x115, x131, 0)
	x141, x142 := bits.Add64(x117, x133, x140)
	x143, x144 := bits.Add64(x119, x135, x142)
	x145, x146 := bits.Add64(x121, x137, x144)
	x147, x148 := bits.Add64(x122+x110, x138+x126, x146)
	x149, x150 := bits.Sub64(x141, 0xfffffffefffffc2f, 0)
	x151, x152 := bits.Sub64(x143, 0xffffffffffffffff, x150)
	x153, x154 := bits.Sub64(x145, 0xffffffffffffffff, x152)
	x155, x156 := bits.Sub64(x147, 0xffffffffffffffff, x154)
	_, x158 := bits.Sub64(x148, 0, x156)
	out1[0] = cmovznz(x158, x149, x141)
	out1[1] = cmovznz(x158, x151, x143)
	out1[2] = cmovznz(x158, x153, x145)
	out1[3] = cmovznz(x158, x155, x147)
}

// toBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	out1 = map (λ X, ⌊((eval arg1 mod m) mod 2^(8 * (X + 1))) / 2^(8 * X)⌋) [0..31]
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
func toBytes(out1 *[32]uint8, arg1 *Element) {
	x1 := arg1[3]
	x2 := arg1[2]
	x3 := arg1[1]
	x4 := arg1[0]
	x5 := uint8(x4) & 0xff
	x6 := x4 >> 8
	x7 := uint8(x6) & 0xff
	x8 := x6 >> 8
	x9 := uint8(x8) & 0xff
	x10 := x8 >> 8
	x11 := uint8(x10) & 0xff
	x12 := x10 >> 8
	x13 := uint8(x12) & 0xff
	x14 := x12 >> 8
	x15 := uint8(x14) & 0xff
	x16 := x14 >> 8
	x17 := uint8(x16) & 0xff
	x18 := uint8(x16 >> 8)
	x19 := uint8(x3) & 0xff
	x20 := x3 >> 8
	x21 := uint8(x20) & 0xff
	x22 := x20 >> 8
	x23 := uint8(x22) & 0xff
	x24 := x22 >> 8
	x25 := uint8(x24) & 0xff
	x26 := x24 >> 8
	x27 := uint8(x26) & 0xff
	x28 := x26 >> 8
	x29 := uint8(x28) & 0xff
	x30 := x28 >> 8
	x31 := uint8(x30) & 0xff
	x32 := uint8(x30 >> 8)
	x33 := uint8(x2) & 0xff
	x34 := x2 >> 8
	x35 := uint8(x34) & 0xff
	x36 := x34 >> 8
	x37 := uint8(x36) & 0xff
	x38 := x36 >> 8
	x39 := uint8(x38) & 0xff
	x40 := x38 >> 8
	x41 := uint8(x40) & 0xff
	x42 := x40 >> 8
	x43 := uint8(x42) & 0xff
	x44 := x42 >> 8
	x45 := uint8(x44) & 0xff
	x46 := uint8(x44 >> 8)
	x47 := uint8(x1) & 0xff
	x48 := x1 >> 8
	x49 := uint8(x48) & 0xff
	x50 := x48 >> 8
	x51 := uint8(x50) & 0xff
	x52 := x50 >> 8
	x53 := uint8(x52) & 0xff
	x54 := x52 >> 8
	x55 := uint8(x54) & 0xff
	x56 := x54 >> 8
	x57 := uint8(x56) & 0xff
	x58 := x56 >> 8
	x59 := uint8(x58) & 0xff
	x60 := uint8(x58 >> 8)
	out1[0] = x5
	out1[1] = x7
	out1[2] = x9
	out1[3] = x11
	out1[4] = x13
	out1[5] = x15
	out1[6] = x17
	out1[7] = x18
	out1[8] = x19
	out1[9] = x21
	out1[10] = x23
	out1[11] = x25
	out1[12] = x27
	out1[13] = x29
	out1[14] = x31
	out1[15] = x32
	out1[16] = x33
	out1[17] = x35
	out1[18] = x37
	out1[19] = x39
	out1[20] = x41
	out1[21] = x43
	out1[22] = x45
	out1[23] = x46
	out1[24] = x47
	out1[25] = x49
	out1[26] = x51
	out1[27] = x53
	out1[28] = x55
	out1[29] = x57
	out1[30] = x59
	out1[31] = x60
}

// fromBytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ bytes_eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = bytes_eval arg1 mod m
//	0 ≤ eval out1 < m
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fromBytes(out1 *Element, arg1 *[32]uint8) {
	x1 := uint64(arg1[31]) << 56
	x2 := uint64(arg1[30]) << 48
	x3 := uint64(arg1[29]) << 40
	x4 := uint64(arg1[28]) << 32
	x5 := uint64(arg1[27]) << 24
	x6 := uint64(arg1[26]) << 16
	x7 := uint64(arg1[25]) << 8
	x8 := arg1[24]
	x9 := uint64(arg1[23]) << 56
	x10 := uint64(arg1[22]) << 48
	x11 := uint64(arg1[21]) << 40
	x12 := uint64(arg1[20]) << 32
	x13 := uint64(arg1[19]) << 24
	x14 := uint64(arg1[18]) << 16
	x15 := uint64(arg1[17]) << 8
	x16 := arg1[16]
	x17 := uint64(arg1[15]) << 56
	x18 := uint64(arg1[14]) << 48
	x19 := uint64(arg1[13]) << 40
	x20 := uint64(arg1[12]) << 32
	x21 := uint64(arg1[11]) << 24
	x22 := uint64(arg1[10]) << 16
	x23 := uint64(arg1[9]) << 8
	x24 := arg1[8]
	x25 := uint64(arg1[7]) << 56
	x26 := uint64(arg1[6]) << 48
	x27 := uint64(arg1[5]) << 40
	x28 := uint64(arg1[4]) << 32
	x29 := uint64(arg1[3]) << 24
	x30 := uint64(arg1[2]) << 16
	x31 := uint64(arg1[1]) << 8
	x32 := arg1[0]
	x33 := x31 + uint64(x32)
	x34 := x30 + x33
	x35 := x29 + x34
	x36 := x28 + x35
	x37 := x27 + x36
	x38 := x26 + x37
	x39 := x25 + x38
	x40 := x23 + uint64(x24)
	x41 := x22 + x40
	x42 := x21 + x41
	x43 := x20 + x42
	x44 := x19 + x43
	x45 := x18 + x44
	x46 := x17 + x45
	x47 := x15 + uint64(x16)
	x48 := x14 + x47
	x49 := x13 + x48
	x50 := x12 + x49
	x51 := x11 + x50
	x52 := x10 + x51
	x53 := x9 + x52
	x54 := x7 + uint64(x8)
	x55 := x6 + x54
	x56 := x5 + x55
	x57 := x4 + x56
	x58 := x3 + x57
	x59 := x2 + x58
	x60 := x1 + x59
	out1[0] = x39
	out1[1] = x46
	out1[2] = x53
	out1[3] = x60
}
