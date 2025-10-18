package main

import (
	"crypto/aes"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/padding"
)

func merkleDamgardAesHash(message []byte, initialState []byte) []byte {
	chunkSize := len(initialState)
	state := initialState

	for i := 0; i < len(message); i += chunkSize {
		paddedMessageChunk := padding.PKCS7Pad(message[i:min(i+chunkSize, len(message))], aes.BlockSize)
		cipher, err := aes.NewCipher(padding.PKCS7Pad(state, aes.BlockSize))
		if err != nil {
			panic(err)
		}

		newState := make([]byte, aes.BlockSize)
		cipher.Encrypt(newState, paddedMessageChunk)

		state = newState[0:chunkSize]
	}

	return state
}

func cheapHash(input []byte) []byte {
	return merkleDamgardAesHash(input, []byte{0, 0})
}

// Finds 2^n collisions in the hash function. Returns them as a slice of
// blocks, where each block contains 2 values that can be used.
func findCollisions(n int, hashFn func([]byte, []byte) []byte, initialState []byte) [][2][]byte {
	byteVariants := make([][2][]byte, n)
	state := initialState

	stateBytes := len(initialState)
	maxBlockValue := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(int64(8*stateBytes)), nil)
	one := big.NewInt(1)

	for i := range n {
		// find two colliding values for byte n

		// map of hash value -> input bytes
		vals := map[string][]byte{}

		foundCollision := false
		for testVal := big.NewInt(0); testVal.Cmp(maxBlockValue) == -1; testVal.Add(testVal, one) {
			testBytes := make([]byte, stateBytes)
			testVal.FillBytes(testBytes)
			testHash := hashFn(testBytes, state)
			testHashKey := string(testHash)

			otherInput, found := vals[testHashKey]
			if found {
				// collision
				foundCollision = true
				byteVariants[i] = [2][]byte{
					testBytes,
					otherInput,
				}
				state = testHash

				fmt.Printf("Found collision for byte %d: %x and %x both hash to %x\n", i, testBytes, otherInput, testHash)
				break
			} else {
				vals[testHashKey] = testBytes
			}
		}

		if !foundCollision {
			panic(fmt.Sprintf("Did not find collision at byte %d", i))
		}
	}

	fmt.Printf("Found collisions:\n")
	for _, pair := range byteVariants {
		fmt.Printf("  %x or %x\n", pair[0], pair[1])
	}
	return byteVariants
}

func yieldCollisions(collisions [][2][]byte) func(yield func(input []byte) bool) {
	return func(yield func(input []byte) bool) {
		for i := 0; i < 1<<len(collisions); i++ {
			bytes := []byte{}
			for blockIdx := 0; blockIdx < len(collisions); blockIdx++ {
				if (i & (1 << blockIdx)) == 0 {
					bytes = append(bytes, collisions[blockIdx][0]...)
				} else {
					bytes = append(bytes, collisions[blockIdx][1]...)
				}
			}

			if !yield(bytes) {
				return
			}
		}
	}
}

func part1() {
	for i := range yieldCollisions(findCollisions(2, merkleDamgardAesHash, []byte{0, 0})) {
		fmt.Printf("H(%x) = %x\n", i, cheapHash(i))
	}
}

func expensiveHash(input []byte) []byte {
	return merkleDamgardAesHash(input, []byte{0, 0, 0})
}

func combinedHash(input []byte) []byte {
	h := cheapHash(input)
	h = append(h, expensiveHash(input)...)

	return h
}

func findBothCollisions() ([]byte, []byte) {
	// map of expensiveHash value -> input bytes
	vals := map[string][]byte{}

	// iterate over a bunch of collisions of cheapHash
	for i := range yieldCollisions(findCollisions(16, merkleDamgardAesHash, []byte{0, 0})) {
		// find a pair of inputs that yields a collision of expensiveHash
		testHash := expensiveHash(i)
		testHashKey := string(testHash)

		otherInput, found := vals[testHashKey]
		if found {
			// collision
			return otherInput, i
		} else {
			vals[testHashKey] = i
		}
	}

	panic("No collisions")
}

func part2() {
	a, b := findBothCollisions()

	fmt.Printf("CH(%x) = %x\nCH(%x) = %x\n", a, combinedHash(a), b, combinedHash(b))
}

func main() {
	part1()
	part2()
}
