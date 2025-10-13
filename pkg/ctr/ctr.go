package ctr

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/benweissmann/cryptopals/pkg/xor"
)

type ctr struct {
	b         cipher.Block
	blockSize int
	nonce     uint64
}

func NewCTRCrypter(b cipher.Block, nonce uint64) *ctr {
	return &ctr{
		b:         b,
		blockSize: b.BlockSize(),
		nonce:     nonce,
	}
}

func (x *ctr) BlockSize() int { return x.blockSize }

func (x *ctr) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr: output smaller than input")
	}

	cryptIn := make([]byte, x.blockSize)
	binary.Encode(cryptIn[0:x.blockSize/2], binary.LittleEndian, x.nonce)

	cryptOut := make([]byte, x.blockSize)

	for blockCount := 0; ; blockCount++ {
		_, err := binary.Encode(cryptIn[x.blockSize/2:x.blockSize], binary.LittleEndian, int64(blockCount))
		if err != nil {
			panic(err.Error())
		}

		x.b.Encrypt(cryptOut, cryptIn)

		start := blockCount * x.blockSize
		end := start + x.blockSize

		if end > len(src) {
			length := len(src) - start
			result := xor.Xor(cryptOut[:length], src[start:])
			copy(dst[start:], result)

			return
		} else {
			result := xor.Xor(cryptOut, src[start:end])
			copy(dst[start:end], result)
		}
	}
}
