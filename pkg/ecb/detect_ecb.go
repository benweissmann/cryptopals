package ecb

import "strings"

const BLOCK_SIZE_BYTES = 128 / 8

func DuplicateBlocks(ciphertext []byte) int {
	repeats := map[string]int{}

	for j := 0; j+BLOCK_SIZE_BYTES <= len(ciphertext); j += BLOCK_SIZE_BYTES {
		block := ciphertext[j : j+BLOCK_SIZE_BYTES]
		repeats[string(block)] = repeats[string(block)] + 1
	}

	maxRepeats := 0
	for _, val := range repeats {
		if val > maxRepeats {
			maxRepeats = val
		}
	}

	return maxRepeats
}

// Returns, in order, the indexes of duplicate blocks in the ciphertext
func DuplicateBlockIndexes(ciphertext []byte) []int {
	blockCounts := map[string]int{}

	for j := 0; j+BLOCK_SIZE_BYTES <= len(ciphertext); j += BLOCK_SIZE_BYTES {
		block := ciphertext[j : j+BLOCK_SIZE_BYTES]
		blockCounts[string(block)] = blockCounts[string(block)] + 1
	}

	repeatIndexes := []int{}
	for j := 0; j+BLOCK_SIZE_BYTES <= len(ciphertext); j += BLOCK_SIZE_BYTES {
		block := ciphertext[j : j+BLOCK_SIZE_BYTES]
		if blockCounts[string(block)] > 1 {
			repeatIndexes = append(repeatIndexes, j/BLOCK_SIZE_BYTES)
		}
	}

	return repeatIndexes
}

func DetectEcb(ciphertexts [][]byte) (index int, ciphertext []byte, nRepeatedBlocks int) {
	bestIndex := -1
	bestIndexRepeats := 0
	var bestCiphertext []byte

	for i, ciphertext := range ciphertexts {
		maxRepeats := DuplicateBlocks(ciphertext)

		if maxRepeats > bestIndexRepeats {
			bestIndex = i
			bestIndexRepeats = maxRepeats
			bestCiphertext = ciphertext
		}
	}

	return bestIndex, bestCiphertext, bestIndexRepeats
}

func DetectEcbFromOracle(oracle func(plaintext []byte) []byte) bool {
	plaintext := strings.Repeat("x", 1000)
	ciphertext := oracle([]byte(plaintext))

	repeats := DuplicateBlocks(ciphertext)
	return repeats > 3
}
