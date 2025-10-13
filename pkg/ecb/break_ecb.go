package ecb

import (
	"bytes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
)

func BreakECBFromOracleWithAttackerControlledPrefix(oracle func(plaintext []byte) []byte) []byte {
	blockSize := DetectBlockSizeFromOracle(oracle)
	fmt.Printf("Detected block size: %d\n", blockSize)

	isECB := DetectEcbFromOracle(oracle)
	if !isECB {
		panic("BreakECBFromOracleWithAttackerControlledPrefix given non-ECB oracle")
	}

	knownPlaintext := bytes.Repeat([]byte{'A'}, blockSize-1)
	paddingLength := blockSize - 1
	block := 0
	nBlocks := len(oracle([]byte{})) / blockSize

	decrypted := []byte{}

	for block < nBlocks {
		fmt.Printf("Breaking next byte.\n  Known plaintext: %s\n  padding length: %d\n  block: %d\n", knownPlaintext, paddingLength, block)

		ciphertext := oracle(bytes.Repeat([]byte{'A'}, paddingLength))
		ciphertextBlock := ciphertext[block*blockSize : (block+1)*blockSize]
		didBreak := false

		for i := 0; i <= 255; i++ {
			testByte := byte(i)
			testBlock := make([]byte, blockSize)
			copy(testBlock[0:blockSize-1], knownPlaintext)
			testBlock[blockSize-1] = testByte

			testCiphertext := oracle(testBlock)[:blockSize]
			if bytes.Equal(testCiphertext, ciphertextBlock) {
				// our guess was right!
				didBreak = true
				decrypted = append(decrypted, testByte)

				newKnownPlaintext := make([]byte, blockSize-1)
				copy(newKnownPlaintext, knownPlaintext[1:])
				newKnownPlaintext[blockSize-2] = testByte

				knownPlaintext = newKnownPlaintext
				if paddingLength > 0 {
					paddingLength--
				} else {
					paddingLength = blockSize - 1
					block++
				}

				fmt.Printf("  Broke byte: %c\n", i)
				break
			}
		}

		if !didBreak {
			return decrypted
		}
	}

	return decrypted
}

func BreakECBFromOracleWithAttackerControlledMiddle(oracle func(plaintext []byte) []byte) []byte {
	blockSize := DetectBlockSizeFromOracle(oracle)
	fmt.Printf("Detected block size: %d\n", blockSize)

	isECB := DetectEcbFromOracle(oracle)
	if !isECB {
		panic("BreakECBFromOracleWithAttackerControlledMiddle given non-ECB oracle")
	}

	// Generate repetitive padding until we construct one that exactly pads the
	// prefix to a block boundary
	prefixPadding := bytes.Repeat([]byte{'A'}, blockSize*3)
	lastDupeCount := DuplicateBlocks(oracle(prefixPadding))
	for {
		newDupeCount := DuplicateBlocks(oracle(prefixPadding))
		if newDupeCount > lastDupeCount {
			break
		}

		prefixPadding = append(prefixPadding, byte('A'))
	}

	// Figure out where our padded data ends
	dupeBlocks := DuplicateBlockIndexes(oracle(prefixPadding))
	prefixPaddingOffset := dupeBlocks[len(dupeBlocks)-1] + 1

	knownPlaintext := bytes.Repeat([]byte{'A'}, blockSize-1)
	paddingLength := blockSize - 1
	block := 0
	nBlocks := (len(oracle(prefixPadding)) / blockSize) - prefixPaddingOffset

	decrypted := []byte{}

	for block < nBlocks {
		fmt.Printf("Breaking next byte.\n  Known plaintext: %s\n  padding length: %d\n  block: %d\n", knownPlaintext, paddingLength, block)

		ciphertext := oracle(convert.ConcatBytes(prefixPadding, bytes.Repeat([]byte{'A'}, paddingLength)))
		ciphertextBlock := ciphertext[(prefixPaddingOffset+block)*blockSize : (prefixPaddingOffset+block+1)*blockSize]
		didBreak := false

		for i := 0; i <= 255; i++ {
			testByte := byte(i)
			testBlock := make([]byte, blockSize)
			copy(testBlock[0:blockSize-1], knownPlaintext)
			testBlock[blockSize-1] = testByte

			testCiphertext := oracle(convert.ConcatBytes(prefixPadding, testBlock))[prefixPaddingOffset*blockSize : (prefixPaddingOffset+1)*blockSize]
			if bytes.Equal(testCiphertext, ciphertextBlock) {
				// our guess was right!
				didBreak = true
				decrypted = append(decrypted, testByte)

				newKnownPlaintext := make([]byte, blockSize-1)
				copy(newKnownPlaintext, knownPlaintext[1:])
				newKnownPlaintext[blockSize-2] = testByte

				knownPlaintext = newKnownPlaintext
				if paddingLength > 0 {
					paddingLength--
				} else {
					paddingLength = blockSize - 1
					block++
				}

				fmt.Printf("  Broke byte: %c\n", i)
				break
			}
		}

		if !didBreak {
			return decrypted
		}
	}

	return decrypted
}
