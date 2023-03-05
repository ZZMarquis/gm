package util

import "bytes"

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func ZeroPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(src, padtext...)
}

// UnZeroPadding
// 由于原文最后一个或若干个字节就有可能为0，所以大多情况下不能简单粗暴地后面有几个0就去掉几个0，除非可以确定最后一个字节肯定不为0.
// 所以需要用户自己去指定具体要去掉末尾几个字节，具体要看用户的自己的数据协议怎么设计。
func UnZeroPadding(src []byte, paddingLen int) []byte {
	return src[:len(src)-paddingLen]
}
