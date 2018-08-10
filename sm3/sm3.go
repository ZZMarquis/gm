package sm3

import (
    "encoding/binary"
    "hash"
    "fmt"
)

const (
    DigestLength = 32
    BlockSize    = 16
    ByteLength   = 64
)

var gT = []uint32{0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC, 0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6, 0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE, 0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5, 0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D, 0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43, 0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE, 0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

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
    d := new(sm3Digest)
    d.Reset()
    return d
}

func (d *sm3Digest) Sum(b []byte) []byte {
    d1 := d
    hash := d1.checkSum()
    return append(b, hash[:]...)
}

// Size returns the number of bytes Sum will return.
func (d *sm3Digest) Size() int {
    return DigestLength
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *sm3Digest) BlockSize() int {
    return BlockSize
}

func (d *sm3Digest) Reset() {
    d.byteCount = 0

    d.xBufOff = 0
    for i := 0; i < len(d.xBuf); i++ {
        d.xBuf[i] = 0
    }

    d.v[0] = 0x7380166F
    d.v[1] = 0x4914B2B9
    d.v[2] = 0x172442D7
    d.v[3] = 0xDA8A0600
    d.v[4] = 0xA96F30BC
    d.v[5] = 0x163138AA
    d.v[6] = 0xE38DEE4D
    d.v[7] = 0xB0FB0E4E

    d.xOff = 0
}

func (d *sm3Digest) Write(p []byte) (n int, err error) {
    _ = p[0]
    len := len(p)

    //
    // fill the current word
    //
    i := 0
    if d.xBufOff != 0 {
        for ; i < len; {
            d.xBuf[d.xBufOff] = p[i]
            d.xBufOff++
            i++
            if d.xBufOff == 4 {
                d.processWord(d.xBuf[:], 0)
                d.xBufOff = 0
                break
            }
        }
    }

    //
    // process whole words.
    //
    limit := ((len - i) & ^3) + i
    for ; i < limit; i += 4 {
        d.processWord(p, int32(0))
    }

    //
    // load in the remainder.
    //
    for ; i < len; {
        d.xBuf[d.xBufOff] = p[i]
        d.xBufOff++
        i++
    }

    d.byteCount += int64(len)

    n = len
    return
}

func (d *sm3Digest) finish() {
    bitLength := d.byteCount << 3

    //
    // add the pad bytes.
    //
    d.Write([]byte{128})

    for ; d.xBufOff != 0; {
        d.Write([]byte{0})
    }

    d.processLength(bitLength)

    d.processBlock()
}

func (d *sm3Digest) checkSum() [DigestLength]byte {
    d.finish()
    vlen := len(d.v)
    var out [DigestLength]byte
    for i := 0; i < vlen; i++ {
        binary.BigEndian.PutUint32(out[i*4:(i+1)*4], d.v[i])
    }
    return out
}

func (d *sm3Digest) processBlock() {
    for j := 0; j < 16; j++ {
        d.w[j] = d.inWords[j]
    }
    for j := 16; j < 68; j++ {
        wj3 := d.w[j-3]
        r15 := (wj3 << 15) | (wj3 >> (32 - 15))
        wj13 := d.w[j-13]
        r7 := (wj13 << 7) | (wj13 >> (32 - 7))
        d.w[j] = p1(d.w[j-16]^d.w[j-9]^r15) ^ r7 ^ d.w[j-6]
    }

    A := d.v[0]
    B := d.v[1]
    C := d.v[2]
    D := d.v[3]
    E := d.v[4]
    F := d.v[5]
    G := d.v[6]
    H := d.v[7]

    for j := 0; j < 16; j++ {
        a12 := (A << 12) | (A >> (32 - 12))
        s1 := a12 + E + gT[j]
        SS1 := (s1 << 7) | (s1 >> (32 - 7))
        SS2 := SS1 ^ a12
        Wj := d.w[j]
        W1j := Wj ^ d.w[j+4]
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
        s1 := a12 + E + gT[j]
        SS1 := (s1 << 7) | (s1 >> (32 - 7))
        SS2 := SS1 ^ a12
        Wj := d.w[j]
        W1j := Wj ^ d.w[j+4]
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

    d.v[0] ^= A
    d.v[1] ^= B
    d.v[2] ^= C
    d.v[3] ^= D
    d.v[4] ^= E
    d.v[5] ^= F
    d.v[6] ^= G
    d.v[7] ^= H

    d.xOff = 0
}

func (d *sm3Digest) processWord(in []byte, inOff int32) {
    // Note: Inlined for performance
    // this.inwords[xOff] = Pack.bigEndianToInt(in, inOff);
    n := binary.BigEndian.Uint32(in[inOff : inOff+4])

    d.inWords[d.xOff] = n
    d.xOff++

    if d.xOff >= 16 {
        d.processBlock()
    }
}

func (d *sm3Digest) processLength(bitLength int64) {
    if d.xOff > (BlockSize - 2) {
        // xOff == 15  --> can't fit the 64 bit length field at tail..
        d.inWords[d.xOff] = 0 // fill with zero
        d.xOff++

        d.processBlock()
    }
    // Fill with zero words, until reach 2nd to last slot
    for ; d.xOff < (BlockSize - 2); d.xOff++ {
        d.inWords[d.xOff] = 0
    }

    // Store input data length in BITS
    d.inWords[d.xOff] = uint32(bitLength >> 32)
    d.xOff++
    d.inWords[d.xOff] = uint32(bitLength)
    d.xOff++
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

    // Different FF,GG functions on rounds 16..63
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
