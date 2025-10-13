package main

import (
	"fmt"
	"math/rand"

	"github.com/benweissmann/cryptopals/pkg/mt"
)

func main() {
	origin := mt.NewGenerator(rand.Uint32())

	var crackedState [624]uint32

	for i := range 624 {
		crackedState[i] = mt.Untemper(origin.Rand())
	}

	cloned := mt.MTState{
		StateArray: crackedState,
		StateIndex: 624,
	}

	for i := range 1000 {
		originalN := origin.Rand()
		clonedN := cloned.Rand()

		fmt.Printf("%d : %d\n", originalN, clonedN)
		if originalN != clonedN {
			panic(fmt.Sprintf("Mismatch at index %d: original %d cloned %d", i, originalN, clonedN))
		}
	}

}
