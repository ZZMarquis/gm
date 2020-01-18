package sm2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

const loopCount = 10

var loopTestSignData = []testSm2SignData{
	{
		d:  "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D",
		x:  "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913",
		y:  "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956",
		in: "0102030405060708010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708010203040506070830450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801",
	},
}

func TestSignVerifyLoop(t *testing.T) {
	priv := new(PrivateKey)
	priv.Curve = GetSm2P256V1()
	dBytes, _ := hex.DecodeString(loopTestSignData[0].d)
	priv.D = new(big.Int).SetBytes(dBytes)

	pub := new(PublicKey)
	pub.Curve = GetSm2P256V1()
	xBytes, _ := hex.DecodeString(loopTestSignData[0].x)
	yBytes, _ := hex.DecodeString(loopTestSignData[0].y)
	pub.X = new(big.Int).SetBytes(xBytes)
	pub.Y = new(big.Int).SetBytes(yBytes)

	for i := 0; i < loopCount; i++ {
		inBytes, _ := hex.DecodeString(loopTestSignData[0].in)
		sign, err := Sign(priv, nil, inBytes)
		if err != nil {
			t.Error(err.Error())
			break
		}

		result := Verify(pub, nil, inBytes, sign)
		if !result {
			t.Error("verify failed")
			break
		}

		fmt.Printf("%d pass\n", i)
	}
}

func TestSignVerifyLoop2(t *testing.T) {
	for i := 0; i < loopCount; i++ {
		priv, pub, err := GenerateKey(rand.Reader)
		if err != nil {
			t.Error(err.Error())
			break
		}

		inBytes, _ := hex.DecodeString(loopTestSignData[0].in)
		sign, err := Sign(priv, nil, inBytes)
		if err != nil {
			t.Error(err.Error())
			break
		}

		result := Verify(pub, nil, inBytes, sign)
		if !result {
			t.Error("verify failed")
			break
		}

		fmt.Printf("%d pass\n", i)
	}
}

func TestSignVerifyLoop3(t *testing.T) {
	priv, pub, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err.Error())
		return
	}

	for i := 0; i < loopCount; i++ {
		inBytes, _ := hex.DecodeString(loopTestSignData[0].in)
		sign, err := Sign(priv, nil, inBytes)
		if err != nil {
			t.Error(err.Error())
			break
		}

		result := Verify(pub, nil, inBytes, sign)
		if !result {
			t.Error("verify failed")
			break
		}

		fmt.Printf("%d pass\n", i)
	}
}
