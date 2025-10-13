package hamming_test

import (
	"fmt"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/hamming"
)

func TestDistance(t *testing.T) {
	in1 := []byte("this is a test")
	in2 := []byte("wokka wokka!!!")

	out := hamming.Distance(in1, in2)
	expected := 37

	if out != expected {
		t.Fatalf("Got %d, expected %d", out, expected)
	}
}

var differingBitTests = []struct {
	in1 byte
	in2 byte
	out int
}{
	{0b00000000, 0b11111111, 8},
	{0b00000000, 0b00000000, 0},
	{0b11111111, 0b00000000, 8},
	{0b11111111, 0b11111111, 0},
	{0b11111110, 0b11111111, 1},
	{0b10000000, 0b11111111, 7},
	{0b00000000, 0b10101100, 4},
}

func TestDifferingBits(t *testing.T) {
	for _, tt := range differingBitTests {
		t.Run(fmt.Sprintf("%08b / %08b -> %d", tt.in1, tt.in2, tt.out), func(t *testing.T) {
			actual := hamming.DifferingBits(tt.in1, tt.in2)
			if actual != tt.out {
				t.Errorf("got %d, want %d", actual, tt.out)
			}
		})
	}
}
