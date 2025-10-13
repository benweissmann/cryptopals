package cbc

import (
	"bytes"

	"github.com/benweissmann/cryptopals/pkg/xor"
)

func PaddingOracle(blockSize int, ciphertext []byte, iv []byte, oracle func(ciphertext []byte, iv []byte) bool) []byte {
	nBlocks := len(ciphertext) / blockSize
	cleartext := []byte{}

	blockIndex := nBlocks - 1
	byteIndex := blockSize - 1
	cleartextBlock := make([]byte, blockSize)
	ciphertextBlock := ciphertext[blockIndex*blockSize : (blockIndex+1)*blockSize]
	prevCiphertextBlock := ciphertext[(blockIndex-1)*blockSize : blockIndex*blockSize]

	for len(cleartext) < len(ciphertext) {
		targetPadding := byte(blockSize - byteIndex)
		for i := 0; ; i++ {
			if i >= 256 {
				panic("Could not crack byte")
			}
			testByte := byte(i)

			testBlock := xor.Xor(xor.Xor(prevCiphertextBlock, cleartextBlock), bytes.Repeat([]byte{targetPadding}, blockSize))

			// try a byte to see if it causes correct padding
			testBlock[byteIndex] = testByte

			var result bool
			result = oracle(ciphertextBlock, testBlock)

			if result {
				// edge case -- if we're working on the last byte, we might have set it
				// to 0x02 rather than 0x01 IF the penultimate byte is 0x02 naturally.
				// If changing the penultimate block and re-submitting also succeeds,
				// was a false positive
				if targetPadding == 1 {
					testBlock2 := make([]byte, len(testBlock))
					copy(testBlock2, testBlock)
					testBlock2[byteIndex-1] ^= 1

					if !oracle(ciphertextBlock, testBlock2) {
						continue
					}
				}

				// padding correct -- we know what the cleartext byte is
				cleartextByte := testByte ^ prevCiphertextBlock[byteIndex] ^ targetPadding

				cleartextBlock[byteIndex] = cleartextByte
				byteIndex--
				break
			}
		}

		if byteIndex < 0 {
			// move to the previous block
			cleartext = append(cleartextBlock, cleartext...)

			if blockIndex > 0 {
				blockIndex--
				byteIndex = blockSize - 1
				cleartextBlock = make([]byte, blockSize)

				ciphertextBlock = prevCiphertextBlock
				if blockIndex == 0 {
					prevCiphertextBlock = iv
				} else {
					prevCiphertextBlock = ciphertext[(blockIndex-1)*blockSize : blockIndex*blockSize]
				}
			}
		}
	}

	return cleartext
}
