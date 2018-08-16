package sm2

import (
    "math/big"
    "crypto/elliptic"
    "io"
    "crypto/rand"
    "hash"
    "encoding/binary"
    "github.com/zz/gm/sm3"
    "github.com/zz/gm/util"
    "errors"
    "bytes"
)

const (
    BitSize = 256
)

var (
    sm2HBytes = new(big.Int).SetInt64(1).Bytes()
)

var sm2P256V1 sm2P256V1Curve

type sm2P256V1Curve struct {
    *elliptic.CurveParams
}

type PublicKey struct {
    x, y  *big.Int
    curve sm2P256V1Curve
}

type PrivateKey struct {
    d     *big.Int
    curve sm2P256V1Curve
}

func init() {
    initSm2P256V1()
}

func initSm2P256V1() {
    sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    //sm2A, _  := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
    sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
    sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
    sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
    sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
    sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
    sm2P256V1.P = sm2P
    sm2P256V1.B = sm2B
    sm2P256V1.N = sm2N
    sm2P256V1.Gx = sm2Gx
    sm2P256V1.Gy = sm2Gy
    sm2P256V1.BitSize = BitSize
}

func GetSm2P256V1() elliptic.Curve {
    return sm2P256V1
}

func GenerateKey(rand io.Reader) (*PrivateKey, *PublicKey, error) {
    priv, x, y, err := elliptic.GenerateKey(sm2P256V1, rand)
    if err != nil {
        return nil, nil, err
    }
    privateKey := new(PrivateKey)
    privateKey.curve = sm2P256V1
    privateKey.d = new(big.Int).SetBytes(priv)
    publicKey := new(PublicKey)
    publicKey.curve = sm2P256V1
    publicKey.x = x
    publicKey.y = y
    return privateKey, publicKey, nil
}

func nextK(rnd io.Reader) (*big.Int, error) {
    k, err := rand.Int(rnd, sm2P256V1.N)
    if err != nil {
        return nil, err
    }
    intOne := new(big.Int).SetInt64(1)
    for k.Cmp(intOne) == -1 {
        k, err = rand.Int(rnd, sm2P256V1.N)
        if err != nil {
            return nil, err
        }
    }
    return k, nil
}

func xor(data []byte, kdfOut []byte, dRemaining int) {
    for i := 0; i != dRemaining; i++ {
        data[i] ^= kdfOut[i]
    }
}

func kdf(hash hash.Hash, c1x *big.Int, c1y *big.Int, encData []byte) {
    bufSize := 4
    if bufSize < hash.BlockSize() {
        bufSize = hash.BlockSize()
    }
    buf := make([]byte, bufSize)

    encDataLen := len(encData)
    c1xBytes := c1x.Bytes()
    c1yBytes := c1y.Bytes()
    off := 0
    ct := uint32(0)
    for off < encDataLen {
        hash.Reset()
        hash.Write(c1xBytes)
        hash.Write(c1yBytes)
        ct++
        binary.BigEndian.PutUint32(buf, ct)
        hash.Write(buf[:4])
        tmp := hash.Sum(nil)
        copy(buf[:bufSize], tmp[:bufSize])

        xorLen := encDataLen - off
        if xorLen > hash.BlockSize() {
            xorLen = hash.BlockSize()
        }
        xor(encData[off:], buf, xorLen)
        off += xorLen
    }
}

func notEncrypted(encData []byte, in []byte) bool {
    encDataLen := len(encData)
    for i := 0; i != encDataLen; i++ {
        if encData[i] != in[0] {
            return false
        }
    }
    return true
}

func Encrypt(pub *PublicKey, in []byte) ([]byte, error) {
    c2 := make([]byte, len(in))
    copy(c2, in)
    var c1 []byte
    digest := sm3.New()
    var kPBx, kPBy *big.Int
    for ; ; {
        k, err := nextK(rand.Reader)
        if err != nil {
            return nil, err
        }
        kBytes := k.Bytes()
        c1x, c1y := pub.curve.ScalarBaseMult(kBytes)
        c1 = elliptic.Marshal(pub.curve, c1x, c1y)
        kPBx, kPBy = pub.curve.ScalarMult(pub.x, pub.y, kBytes)
        kdf(digest, kPBx, kPBy, c2)

        if !notEncrypted(c2, in) {
            break
        }
    }

    digest.Reset()
    digest.Write(kPBx.Bytes())
    digest.Write(in)
    digest.Write(kPBy.Bytes())
    c3 := digest.Sum(nil)

    c1Len := len(c1)
    c2Len := len(c2)
    c3Len := len(c3)
    result := make([]byte, c1Len+c2Len+c3Len)
    copy(result[:c1Len], c1)
    copy(result[c1Len:c1Len+c2Len], c2)
    copy(result[c1Len+c2Len:], c3)
    return result, nil
}

func Decrypt(priv *PrivateKey, in []byte) ([]byte, error) {
    c1Len := ((priv.curve.BitSize+7)/8)*2 + 1
    c1 := make([]byte, c1Len)
    copy(c1, in[:c1Len])
    c1x, c1y := elliptic.Unmarshal(priv.curve, c1)
    sx, sy := priv.curve.ScalarMult(c1x, c1y, sm2HBytes)
    if util.IsEcPointInfinity(sx, sy) {
        return nil, errors.New("[h]C1 at infinity")
    }
    c1x, c1y = priv.curve.ScalarMult(c1x, c1y, priv.d.Bytes())

    digest := sm3.New()
    c3Len := digest.Size()
    c2Len := len(in) - c1Len - c3Len
    c2 := make([]byte, c2Len)
    copy(c2, in[c1Len:c1Len+c2Len])
    kdf(digest, c1x, c1y, c2)

    digest.Reset()
    digest.Write(c1x.Bytes())
    digest.Write(c2)
    digest.Write(c1y.Bytes())
    c3 := digest.Sum(nil)

    if !bytes.Equal(c3, in[c1Len+c2Len:]) {
        return nil, errors.New("invalid cipher text")
    }
    return c2, nil
}
