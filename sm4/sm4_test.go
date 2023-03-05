package sm4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ZZMarquis/gm/util"
	"testing"
)

type sm4CbcTestData struct {
	key []byte
	iv  []byte
	in  []byte
	out []byte
}

var cbcTestData = []sm4CbcTestData{
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0xca, 0x55, 0xc5, 0x15, 0x0b, 0xf7, 0xf4, 0x6f, 0xc9, 0x89, 0x2a, 0xce, 0x49, 0x78, 0x93, 0x03},
	},
	{
		key: []byte{0x7b, 0xea, 0x0a, 0xa5, 0x45, 0x8e, 0xd1, 0xa3, 0x7d, 0xb1, 0x65, 0x2e, 0xfb, 0xc5, 0x95, 0x05},
		iv:  []byte{0x70, 0xb6, 0xe0, 0x8d, 0x46, 0xee, 0x82, 0x24, 0x45, 0x60, 0x0b, 0x25, 0xc4, 0x71, 0xfa, 0xba},
		in:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		out: []byte{0x95, 0xe1, 0xec, 0x3b, 0x56, 0x4a, 0x46, 0x71, 0xe7, 0xd6, 0xb1, 0x10, 0xe9, 0x09, 0x0b, 0x1b, 0xb7, 0xb5, 0x9e, 0x8d, 0x74, 0x47, 0x1e, 0x70, 0x86, 0x04, 0x6b, 0xe8, 0x78, 0x00, 0x45, 0x32},
	},
}

func TestSm4_CBC_Encrypt(t *testing.T) {
	for _, data := range cbcTestData {
		fmt.Printf("Key:%s\n", hex.EncodeToString(data.key))
		fmt.Printf("IV:%s\n", hex.EncodeToString(data.iv))

		cipherText, err := CBCEncrypt(data.key, data.iv, util.PKCS5Padding(data.in, BlockSize))
		if err != nil {
			t.Error(err.Error())
			return
		}
		fmt.Printf("encrypt cipherText:%s\n", hex.EncodeToString(cipherText))
		if !bytes.Equal(cipherText, data.out) {
			t.Error("encrypt cipherText not equal expected")
			return
		}

		plainTextWithPadding, err := CBCDecrypt(data.key, data.iv, cipherText)
		if err != nil {
			t.Error(err.Error())
			return
		}
		fmt.Printf("decrypt cipherText:%s\n", hex.EncodeToString(plainTextWithPadding))
		plainText := util.PKCS5UnPadding(plainTextWithPadding)
		if !bytes.Equal(plainText, data.in) {
			t.Error("decrypt cipherText not equal expected")
			return
		}
	}
}

type sm4EcbTestData struct {
	key []byte
	in  []byte
}

var ecbTestData = []sm4EcbTestData{
	{
		key: []byte("1234567890123456"),
		in:  []byte("ssssssss"),
	}, {
		key: []byte("1234567890123456"),
		in:  []byte("ssssssssssssssss"),
	}, {
		key: []byte("1234567890123456"),
		in:  []byte("ssssssssssssssssssssssss"),
	},
}

func TestSm4_ECB_Encrypt_PKCS5Padding(t *testing.T) {
	for _, testData := range ecbTestData {
		plainTextWithPadding := util.PKCS5Padding(testData.in, BlockSize)
		cipherText, err := ECBEncrypt(testData.key, plainTextWithPadding)
		if err != nil {
			t.Error(err.Error())
			return
		}
		fmt.Printf("%x\n", cipherText)

		plainTextWithPadding, err = ECBDecrypt(testData.key, cipherText)
		if err != nil {
			t.Error(err.Error())
			return
		}
		plainText := util.PKCS5UnPadding(plainTextWithPadding)
		fmt.Println(string(plainText))
		if !bytes.Equal(testData.in, plainText) {
			t.Error("decrypt result not equal expected")
			return
		}
	}
}

func TestSm4_ECB_Encrypt_ZeroPadding(t *testing.T) {
	for _, testData := range ecbTestData {
		plainTextWithPadding := util.ZeroPadding(testData.in, BlockSize)
		paddingLen := len(plainTextWithPadding) - len(testData.in)
		cipherText, err := ECBEncrypt(testData.key, plainTextWithPadding)
		if err != nil {
			t.Error(err.Error())
			return
		}
		fmt.Printf("%x\n", cipherText)

		plainTextWithPadding, err = ECBDecrypt(testData.key, cipherText)
		if err != nil {
			t.Error(err.Error())
			return
		}
		plainText := util.UnZeroPadding(plainTextWithPadding, paddingLen)
		fmt.Println(string(plainText))
		if !bytes.Equal(testData.in, plainText) {
			t.Error("decrypt result not equal expected")
			return
		}
	}
}
