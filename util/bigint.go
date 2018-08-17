package util

import "math/big"

func Add(x, y *big.Int) *big.Int {
    var z big.Int
    z.Add(x, y)
    return &z
}

func Sub(x, y *big.Int) *big.Int {
    var z big.Int
    z.Sub(x, y)
    return &z
}

func Mod(x, y *big.Int) *big.Int {
    var z big.Int
    z.Mod(x, y)
    return &z
}


func ModInverse(x, y *big.Int) *big.Int {
    var z big.Int
    z.ModInverse(x, y)
    return &z
}

func Mul(x, y *big.Int) *big.Int {
    var z big.Int
    z.Mul(x, y)
    return &z
}
