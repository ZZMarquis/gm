package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
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
		return
	}
	fmt.Printf("priv:%s\n", priv.D.Text(16))
	fmt.Printf("x:%s\n", pub.X.Text(16))
	fmt.Printf("y:%s\n", pub.Y.Text(16))

	curve := GetSm2P256V1()
	if !curve.IsOnCurve(pub.X, pub.Y) {
		t.Error("x,y is not on Curve")
		return
	}
	fmt.Println("x,y is on sm2 Curve")
}

func TestEncryptDecrypt(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	cipherText, err := Encrypt(pub, src)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

	plainText, err := Decrypt(priv, cipherText)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

	if !bytes.Equal(plainText, src) {
		t.Error("decrypt result not equal expected")
		return
	}
}

func TestCipherDerEncode(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	cipherText, err := Encrypt(pub, src)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("cipher text:%s\n", hex.EncodeToString(cipherText))

	derCipher, err := MarshalCipher(cipherText)
	if err != nil {
		t.Error(err.Error())
		return
	}
	//err = ioutil.WriteFile("derCipher.dat", derCipher, 0644)
	//if err != nil {
	//	t.Error(err.Error())
	//	return
	//}
	cipherText, err = UnmarshalCipher(derCipher)
	if err != nil {
		t.Error(err.Error())
		return
	}

	plainText, err := Decrypt(priv, cipherText)
	if err != nil {
		t.Error(err.Error())
		return
	}
	fmt.Printf("plain text:%s\n", hex.EncodeToString(plainText))

	if !bytes.Equal(plainText, src) {
		t.Error("decrypt result not equal expected")
		return
	}
}

type testSm2SignData struct {
	d    string
	x    string
	y    string
	in   string
	sign string
}

var testSignData = []testSm2SignData{
	{
		d:    "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D",
		x:    "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913",
		y:    "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956",
		in:   "0102030405060708010203040506070801020304050607080102030405060708",
		sign: "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801",
	},
}

func TestSign(t *testing.T) {
	for _, data := range testSignData {
		priv := new(PrivateKey)
		priv.Curve = GetSm2P256V1()
		dBytes, _ := hex.DecodeString(data.d)
		priv.D = new(big.Int).SetBytes(dBytes)
		inBytes, _ := hex.DecodeString(data.in)
		sign, err := Sign(priv, nil, inBytes)
		if err != nil {
			t.Error(err.Error())
			return
		}
		fmt.Printf("sign:%s\n", hex.EncodeToString(sign))

		pub := new(PublicKey)
		pub.Curve = GetSm2P256V1()
		xBytes, _ := hex.DecodeString(data.x)
		yBytes, _ := hex.DecodeString(data.y)
		pub.X = new(big.Int).SetBytes(xBytes)
		pub.Y = new(big.Int).SetBytes(yBytes)
		result := Verify(pub, nil, inBytes, sign)
		if !result {
			t.Error("verify failed")
			return
		}
	}
}

func TestVerify(t *testing.T) {
	for _, data := range testSignData {
		pub := new(PublicKey)
		pub.Curve = GetSm2P256V1()
		xBytes, _ := hex.DecodeString(data.x)
		yBytes, _ := hex.DecodeString(data.y)
		pub.X = new(big.Int).SetBytes(xBytes)
		pub.Y = new(big.Int).SetBytes(yBytes)
		inBytes, _ := hex.DecodeString(data.in)
		sign, _ := hex.DecodeString(data.sign)
		result := Verify(pub, nil, inBytes, sign)
		if !result {
			t.Error("verify failed")
			return
		}
	}
}
