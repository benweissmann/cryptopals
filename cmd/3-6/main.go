package main

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/benweissmann/cryptopals/pkg/mt"
)

func crackSeed(now time.Time, output uint32) uint32 {
	for i := uint32(now.Unix()); i > 0; i-- {
		if mt.NewGenerator(i).Rand() == output {
			return i
		}
	}

	return 0
}

func main() {
	now := time.Now()
	now = now.Add(time.Second * time.Duration(rand.N(1000)))

	seed := uint32(now.Unix())
	rng := mt.NewGenerator(seed)

	now = now.Add(time.Second * time.Duration(rand.N(1000)))

	cracked := crackSeed(now, rng.Rand())

	fmt.Printf("Cracked: %d - Correct: %d\n", cracked, seed)
}
