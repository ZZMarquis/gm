package util

import (
	"fmt"
	"math/big"
	"testing"
)

func TestAdd(t *testing.T) {
	a := new(big.Int).SetInt64(1)
	b := new(big.Int).SetInt64(1)
	a.Add(a, b)
	fmt.Printf("a:%s\n", a.Text(10))
	fmt.Printf("b:%s\n", b.Text(10))
}

func TestAdd2(t *testing.T) {
	a := new(big.Int).SetInt64(1)
	b := new(big.Int).SetInt64(1)
	z := Add(a, b)
	fmt.Printf("a:%s\n", a.Text(10))
	fmt.Printf("b:%s\n", b.Text(10))
	fmt.Printf("z:%s\n", z.Text(10))
}
