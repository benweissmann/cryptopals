package cbc

import (
	"crypto/cipher"

	"github.com/benweissmann/cryptopals/pkg/xor"
)

type cbc struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

type cbcEncrypter cbc

func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cbc: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("cbc: output smaller than input")
	}

	iv := x.iv
	for i := 0; i < len(dst); i += x.blockSize {
		start := i
		end := i + x.blockSize

		cryptIn := xor.Xor(src[start:end], iv)

		x.b.Encrypt(dst[start:end], cryptIn)
		iv = dst[start:end]
	}
}

type cbcDecrypter cbc

func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        iv,
	}
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cbc: input not full blocks")
	}

	if len(dst) < len(src) {
		panic("cbc: output smaller than input")
	}

	iv := x.iv
	for i := 0; i < len(dst); i += x.blockSize {
		start := i
		end := i + x.blockSize

		cryptOut := make([]byte, x.blockSize)
		x.b.Decrypt(cryptOut, src[start:end])

		plaintextBlock := xor.Xor(cryptOut, iv)

		copy(dst[start:end], plaintextBlock)
		iv = src[start:end]
	}
}
