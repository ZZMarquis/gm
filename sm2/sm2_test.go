package sm2

import (
    "testing"
    "fmt"
    "crypto/rand"
    "encoding/hex"
    "bytes"
)

func TestGetSm2P256V1(t *testing.T) {
    curve := GetSm2P256V1()
    fmt.Printf("P:%s\n", curve.Params().P.Text(16))
    fmt.Printf("B:%s\n", curve.Params().B.Text(16))
    fmt.Printf("N:%s\n", curve.Params().N.Text(16))
    fmt.Printf("Gx:%s\n", curve.Params().Gx.Text(16))
    fmt.Printf("Gy:%s\n", curve.Params().Gy.Text(16))
}

func TestGenerateKey(t *testing.T) {
    priv, pub, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Error(err.Error())
    }
    fmt.Printf("priv:%s\n", priv.d.Text(16))
    fmt.Printf("x:%s\n", pub.x.Text(16))
    fmt.Printf("y:%s\n", pub.y.Text(16))

    curve := GetSm2P256V1()
    if !curve.IsOnCurve(pub.x, pub.y) {
        t.Error("x,y is not on curve")
    }
    fmt.Println("x,y is on sm2 curve")
}

func TestEncryptDecrypt(t *testing.T) {
    src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
    priv, pub, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Error(err.Error())
    }

    cipherText, err := Encrypt(pub, src)
    if err != nil {
        t.Error(err.Error())
    }
    fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

    plainText, err := Decrypt(priv, cipherText)
    if err != nil {
        t.Error(err.Error())
    }
    fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

    if !bytes.Equal(plainText, src) {
        t.Error("decrypt result not equal expected")
    }
}
