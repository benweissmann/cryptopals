package mt

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/benweissmann/cryptopals/pkg/xor"
)

type mtcrypt struct {
	state *MTState
}

func NewMTCrypter(seed uint16) cipher.BlockMode {
	return &mtcrypt{
		state: NewGenerator(uint32(seed)),
	}
}

func (x *mtcrypt) BlockSize() int { return 4 }

func (x *mtcrypt) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr: output smaller than input")
	}

	for i := 0; i < len(src); i++ {
		end := min(i+4, len(src))

		keystream := make([]byte, 4)
		binary.LittleEndian.PutUint32(keystream, x.state.Rand())

		res := xor.Xor(keystream[0:(end-i)], src[i:end])

		copy(dst[i:end], res)
	}
}
