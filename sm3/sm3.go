package sm3

import (
    "fmt"
    "encoding/binary"
)

const (
    DigestLength = 32
    BlockSize    = 16
    ByteLength   = 64
)

var t = [64]uint32 {0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC, 0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6, 0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE, 0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5, 0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D, 0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43, 0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE, 0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

type SM3Digest struct {
    v [DigestLength / 4]uint32
    inWords [BlockSize]uint32
    xOff int32
    w [68]uint32
    xBuf [4]byte
    xBufOff int32
    byteCount int64
}

func p0(x uint32) uint32 {
    r9 := (x << 9) | (x >> (32 - 9))
    r17 := (x << 17) | (x >> (32 - 17))
    return x ^ r9 ^ r17
}

func p1(x uint32) uint32 {
    r15 := (x << 15) | (x >> (32 - 15))
    r23 := (x << 23) | (x >> (32 - 23))
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

func (digest *SM3Digest) reset()  {
    digest.byteCount = 0

    digest.xBufOff = 0
    for i := 0; i < len(digest.xBuf); i++ {
        digest.xBuf[i] = 0
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

func (digest *SM3Digest) processBlock()  {
    for j := 0; j < 16; j++ {
        digest.w[j] = digest.inWords[j];
    }
    for j := 16; j < 68; j++ {
        wj3 := digest.w[j-3];
        r15 := (wj3 << 15) | (wj3 >> (32 - 15))
        wj13 := digest.w[j-13];
        r7 := (wj13 << 7) | (wj13 >> (32 - 7))
        digest.w[j] = p1(digest.w[j-16]^digest.w[j-9]^r15) ^ r7 ^ digest.w[j-6];
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
        s1 := a12 + E + t[j]
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

    // Different FF,GG functions on rounds 16..63
    for j := 16; j < 64; j++ {
        a12 := (A << 12) | (A >> (32 - 12))
        s1 := a12 + E + t[j]
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

func (digest *SM3Digest) processWord(in []byte, inOff int32) {
    // Note: Inlined for performance
    // this.inwords[xOff] = Pack.bigEndianToInt(in, inOff);
    n := binary.BigEndian.Uint32(in[inOff : inOff + 4])

    digest.inWords[digest.xOff] = n
    digest.xOff++

    if digest.xOff >= 16 {
        digest.processBlock()
    }
}

func (digest *SM3Digest) processLength(bitLength int64)  {
    if digest.xOff > (BlockSize - 2) {
        // xOff == 15  --> can't fit the 64 bit length field at tail..
        digest.inWords[digest.xOff] = 0 // fill with zero
        digest.xOff++

        digest.processBlock();
    }
    // Fill with zero words, until reach 2nd to last slot
    for ; digest.xOff < (BlockSize - 2); digest.xOff++ {
        digest.inWords[digest.xOff] = 0
    }

    // Store input data length in BITS
    digest.inWords[digest.xOff] = uint32(bitLength >> 32)
    digest.xOff++
    digest.inWords[digest.xOff] = uint32(bitLength)
    digest.xOff++
}

func PrintT()  {
    for i := uint32(0); i < 16; i++ {
        tTmp := uint32(0x79CC4519)
        t[i] = (tTmp << i) | (tTmp >> (32 - i))
        fmt.Printf("0x%08X, ", t[i])
    }
    for i := uint32(16); i < 64; i++ {
        n := i % 32
        tTmp := uint32(0x7A879D8A)
        t[i] = (tTmp << n) | (tTmp >> (32 - n))
        fmt.Printf("0x%08X, ", t[i])
    }
    fmt.Println()
}
