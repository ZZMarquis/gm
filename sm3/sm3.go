package sm3

import (
	"encoding/binary"
	"fmt"
	"hash"
	"math/bits"
)

const (
	DigestLength = 32
	BlockSize    = 16
)

var gT = []uint32{
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
	0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

type sm3Digest struct {
	v         [DigestLength / 4]uint32
	inWords   [BlockSize]uint32
	xOff      int32
	w         [68]uint32
	xBuf      [4]byte
	xBufOff   int32
	byteCount int64
}

func New() hash.Hash {
	digest := new(sm3Digest)
	digest.Reset()
	return digest
}

func (digest *sm3Digest) Sum(b []byte) []byte {
	d1 := digest
	h := d1.checkSum()
	return append(b, h[:]...)
}

// Size returns the number of bytes Sum will return.
func (digest *sm3Digest) Size() int {
	return DigestLength
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (digest *sm3Digest) BlockSize() int {
	return BlockSize
}

func (digest *sm3Digest) Reset() {
	digest.byteCount = 0

	digest.xBufOff = 0
	for i := 0; i < len(digest.xBuf); i++ {
		digest.xBuf[i] = 0
	}

	for i := 0; i < len(digest.inWords); i++ {
		digest.inWords[i] = 0
	}

	for i := 0; i < len(digest.w); i++ {
		digest.w[i] = 0
	}

	digest.v[0] = 0x7380166F
	digest.v[1] = 0x4914B2B9
	digest.v[2] = 0x172442D7
	digest.v[3] = 0xDA8A0600
	digest.v[4] = 0xA96F30BC
	digest.v[5] = 0x163138AA
	digest.v[6] = 0xE38DEE4D
	digest.v[7] = 0xB0FB0E4E

	digest.xOff = 0
}

func (digest *sm3Digest) Write(p []byte) (n int, err error) {
	_ = p[0]
	inLen := len(p)

	i := 0
	if digest.xBufOff != 0 {
		for i < inLen {
			digest.xBuf[digest.xBufOff] = p[i]
			digest.xBufOff++
			i++
			if digest.xBufOff == 4 {
				digest.processWord(digest.xBuf[:], 0)
				digest.xBufOff = 0
				break
			}
		}
	}

	limit := ((inLen - i) & ^3) + i
	for ; i < limit; i += 4 {
		digest.processWord(p, int32(i))
	}

	for i < inLen {
		digest.xBuf[digest.xBufOff] = p[i]
		digest.xBufOff++
		i++
	}

	digest.byteCount += int64(inLen)

	n = inLen
	return
}

func (digest *sm3Digest) finish() {
	bitLength := digest.byteCount << 3

	digest.Write([]byte{128})

	for digest.xBufOff != 0 {
		digest.Write([]byte{0})
	}

	digest.processLength(bitLength)

	digest.processBlock()
}

func (digest *sm3Digest) checkSum() [DigestLength]byte {
	digest.finish()
	vlen := len(digest.v)
	var out [DigestLength]byte
	for i := 0; i < vlen; i++ {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], digest.v[i])
	}
	return out
}

func (digest *sm3Digest) processBlock() {
	for j := 0; j < 16; j++ {
		digest.w[j] = digest.inWords[j]
	}
	for j := 16; j < 68; j++ {
		wj3 := digest.w[j-3]
		r15 := (wj3 << 15) | (wj3 >> (32 - 15))
		wj13 := digest.w[j-13]
		r7 := (wj13 << 7) | (wj13 >> (32 - 7))
		digest.w[j] = p1(digest.w[j-16]^digest.w[j-9]^r15) ^ r7 ^ digest.w[j-6]
	}

	A := digest.v[0]
	B := digest.v[1]
	C := digest.v[2]
	D := digest.v[3]
	E := digest.v[4]
	F := digest.v[5]
	G := digest.v[6]
	H := digest.v[7]

	for j := 0; j < 16; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := digest.w[j]
		W1j := Wj ^ digest.w[j+4]
		TT1 := ff0(A, B, C) + D + SS2 + W1j
		TT2 := gg0(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	for j := 16; j < 64; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := digest.w[j]
		W1j := Wj ^ digest.w[j+4]
		TT1 := ff1(A, B, C) + D + SS2 + W1j
		TT2 := gg1(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	digest.v[0] ^= A
	digest.v[1] ^= B
	digest.v[2] ^= C
	digest.v[3] ^= D
	digest.v[4] ^= E
	digest.v[5] ^= F
	digest.v[6] ^= G
	digest.v[7] ^= H

	digest.xOff = 0
}

func (digest *sm3Digest) processWord(in []byte, inOff int32) {
	n := binary.BigEndian.Uint32(in[inOff : inOff+4])

	digest.inWords[digest.xOff] = n
	digest.xOff++

	if digest.xOff >= 16 {
		digest.processBlock()
	}
}

func (digest *sm3Digest) processLength(bitLength int64) {
	if digest.xOff > (BlockSize - 2) {
		digest.inWords[digest.xOff] = 0
		digest.xOff++

		digest.processBlock()
	}

	for ; digest.xOff < (BlockSize - 2); digest.xOff++ {
		digest.inWords[digest.xOff] = 0
	}

	digest.inWords[digest.xOff] = uint32(bitLength >> 32)
	digest.xOff++
	digest.inWords[digest.xOff] = uint32(bitLength)
	digest.xOff++
}

func p0(x uint32) uint32 {
	r9 := bits.RotateLeft32(x, 9)
	r17 := bits.RotateLeft32(x, 17)
	return x ^ r9 ^ r17
}

func p1(x uint32) uint32 {
	r15 := bits.RotateLeft32(x, 15)
	r23 := bits.RotateLeft32(x, 23)
	return x ^ r15 ^ r23
}

func ff0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

func ff1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func gg0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

func gg1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func Sum(data []byte) [DigestLength]byte {
	var d sm3Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func PrintT() {
	var T [64]uint32
	fmt.Print("{")
	for j := 0; j < 16; j++ {
		T[j] = 0x79CC4519
		Tj := (T[j] << uint32(j)) | (T[j] >> (32 - uint32(j)))
		fmt.Printf("0x%08X, ", Tj)
	}

	for j := 16; j < 64; j++ {
		n := j % 32
		T[j] = 0x7A879D8A
		Tj := (T[j] << uint32(n)) | (T[j] >> (32 - uint32(n)))
		if j == 63 {
			fmt.Printf("0x%08X}\n", Tj)
		} else {
			fmt.Printf("0x%08X, ", Tj)
		}
	}
}
