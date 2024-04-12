package schnorrq

import (
	"fmt"
	"math/big"
)

var (
	montgomery_RPrime = [32]byte{
		0x00, 0x06, 0xA5, 0xF1, 0x6A, 0xC8, 0xF9, 0xD3,
		0x3D, 0x01, 0xB7, 0xC7, 0x21, 0x36, 0xF6, 0x1C,
		0x17, 0x3E, 0xA5, 0xAA, 0xEA, 0x6B, 0x38, 0x7D,
		0xC8, 0x1D, 0xB8, 0x79, 0x5F, 0xF3, 0xD6, 0x21,
	}
	M_RP = new(big.Int).SetBytes(montgomery_RPrime[:])

	montgometry_rPrime = [32]byte{
		0xF3, 0x27, 0x02, 0xFD, 0xAF, 0xC1, 0xC0, 0x74,
		0xBC, 0xE4, 0x09, 0xED, 0x76, 0xB5, 0xDB, 0x21,
		0xD7, 0x5E, 0x78, 0xB8, 0xD1, 0xFC, 0xDC, 0xF3,
		0xE1, 0x2F, 0xE5, 0xF0, 0x79, 0xBC, 0x39, 0x29,
	}
	M_rP = new(big.Int).SetBytes(montgometry_rPrime[:])

	curveOrder = [32]byte{
		0x00, 0x29, 0xcb, 0xc1, 0x4e, 0x5e, 0x0a, 0x72,
		0xf0, 0x53, 0x97, 0x82, 0x9c, 0xbc, 0x14, 0xe5,
		0xdf, 0xbd, 0x00, 0x4d, 0xfe, 0x0f, 0x79, 0x99,
		0x2f, 0xb2, 0x54, 0x0e, 0xc7, 0x76, 0x8c, 0xe7,
	}

	orderBI = new(big.Int).SetBytes(curveOrder[:])
)

type Montgomery struct {
	modulus      *big.Int // Modulus (order)
	reciprocal   *big.Int // Reciprocal of modulus
	mPrime       *big.Int // -1/modulus
	r            *big.Int // R = 2^bitsize of modulus
	rInverse     *big.Int // R^-1 mod modulus
	rSquared     *big.Int // R^2 mod modulus
	modulusMinus *big.Int // Modulus - 1
}

// NewMontgomery creates a new Montgomery struct.
func NewMontgomery() *Montgomery {
	m := new(Montgomery)
	m.modulus = orderBI
	m.reciprocal = new(big.Int).ModInverse(big.NewInt(2), orderBI)
	m.mPrime = new(big.Int).Neg(orderBI)
	m.r = M_rP
	//new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(modulus.BitLen())), nil)
	m.rInverse = new(big.Int).ModInverse(m.r, orderBI)
	m.rSquared = new(big.Int).Exp(m.r, big.NewInt(2), orderBI)
	m.modulusMinus = new(big.Int).Sub(orderBI, big.NewInt(1))
	return m
}

// Multiply performs Montgomery multiplication modulo the given modulus.
func (m *Montgomery) Multiply(x, y *big.Int) *big.Int {
	// Compute t = x*y*R^-1 mod modulus
	t := new(big.Int).Mul(x, y)
	t.Mul(t, m.rInverse)
	t.Mod(t, m.modulus)

	// Compute m mod R
	mModR := new(big.Int).Mul(m.modulus, m.modulusMinus)
	mModR.Mod(mModR, m.r)

	// Compute u = (t + ((t*m') mod R) * modulus) / R
	u := new(big.Int).Add(t, new(big.Int).Mul(t, m.mPrime))
	u.Mul(u, m.reciprocal)
	u.Mod(u, m.r)
	if u.Cmp(m.modulus) >= 0 {
		u.Sub(u, m.modulus)
	}

	// Adjust the result based on comparison of cout and bout (constant-time subtraction)
	mask := new(big.Int).Sub(t, u)
	intMask := mask.BitLen() >> 63 // If t >= u, mask = 0x00..0; else mask = 0xFF..F
	mask = big.NewInt(int64(intMask))

	// Add the mask & r to the result
	temp := new(big.Int).Mul(m.modulus, m.modulusMinus)
	temp.Mod(temp, m.r)
	temp.And(temp, mask)
	u.Add(u, temp)

	fmt.Println(len(u.Bytes()))

	return u
}
