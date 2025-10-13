package mt_test

import (
	"math"
	"testing"
	"time"

	"github.com/benweissmann/cryptopals/pkg/mt"
	"gonum.org/v1/gonum/mathext/prng"
)

func TestMTDefaultSeed(t *testing.T) {
	gen := mt.NewGenerator(5489)
	ref := prng.NewMT19937()
	ref.Seed(5489)

	for i := range 10000 {
		actual := gen.Rand()
		expected := ref.Uint32()

		if actual != expected {
			t.Fatalf("Iteraction %d: got %d expected %d float %f", i, actual, expected, float64(actual)/math.MaxUint32)
		}
	}
}

func TestMTZeroSeed(t *testing.T) {
	gen := mt.NewGenerator(0)
	ref := prng.NewMT19937()
	ref.Seed(0)

	for i := range 10000 {
		actual := gen.Rand()
		expected := ref.Uint32()

		if actual != expected {
			t.Fatalf("Iteraction %d: got %d expected %d float %f", i, actual, expected, float64(actual)/math.MaxUint32)
		}
	}
}

func TestMTCurrentTime(t *testing.T) {
	now := time.Now()

	gen := mt.NewGenerator(uint32(now.Unix()))
	ref := prng.NewMT19937()
	ref.Seed(uint64(now.Unix()))

	for i := range 10000 {
		actual := gen.Rand()
		expected := ref.Uint32()

		if actual != expected {
			t.Fatalf("Iteraction %d: got %d expected %d float %f", i, actual, expected, float64(actual)/math.MaxUint32)
		}
	}
}
