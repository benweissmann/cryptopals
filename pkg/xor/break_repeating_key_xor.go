package xor

import (
	"fmt"
	"math"

	"github.com/benweissmann/cryptopals/pkg/hamming"
)

const MIN_KEYSIZE = 2
const MAX_KEYSIZE = 40

func GetRepeatingKeyXorKeySize(ciphertext []byte) int {
	blocksToCompare := len(ciphertext) / MAX_KEYSIZE
	if blocksToCompare < 2 {
		panic(fmt.Sprintf("Ciphertext too short: got %d bytes, need %d", len(ciphertext), MAX_KEYSIZE*2))
	}

	smallestDist := math.MaxFloat64
	bestKeysize := 0

	for i := MIN_KEYSIZE; i <= MAX_KEYSIZE; i++ {
		distances := make([]int, blocksToCompare)
		for j := 0; j < blocksToCompare; j++ {
			block1 := ciphertext[j*i : (j+1)*i]
			block2 := ciphertext[(j+1)*i : (j+2)*i]

			distances[j] = hamming.Distance(block1, block2)
		}

		totalDist := 0
		for _, dist := range distances {
			totalDist += dist
		}

		normalizedDist := (float64(totalDist) / float64(i)) / float64(blocksToCompare)

		// fmt.Printf("Block size %d: dist %f\n", i, normalizedDist)

		if normalizedDist < smallestDist {
			smallestDist = normalizedDist
			bestKeysize = i
		}
	}

	return bestKeysize
}

func BreakRepeatingKeyXor(ciphertext []byte, keysize int) (key string, plaintext string) {
	repeatingCiphertexts := make([][]byte, keysize)
	for i := 0; i < keysize; i++ {
		repeatingCiphertexts[i] = []byte{}
	}

	for i := 0; i < len(ciphertext); i++ {
		repeatingCiphertexts[i%keysize] = append(repeatingCiphertexts[i%keysize], ciphertext[i])
	}

	finalPlaintext := make([]byte, len(ciphertext))
	finalKey := make([]byte, keysize)
	for i := 0; i < keysize; i++ {
		plaintext, key, _ := BreakSingleCharXor(repeatingCiphertexts[i])

		for j := 0; j < len(plaintext); j++ {
			finalPlaintext[j*keysize+i] = plaintext[j]
		}

		finalKey[i] = key
	}

	return string(finalKey), string(finalPlaintext)
}
