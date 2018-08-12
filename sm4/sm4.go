package sm4

const (
    BlockSize = 16
)

type sm4Cipher struct {
}

func (c *sm4Cipher) BlockSize() int  {
    return BlockSize
}


