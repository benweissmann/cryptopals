package mt

import (
	"fmt"
	"testing"
)

func TestRightUntemperU(t *testing.T) {
	input := uint32(3294967295)

	fmt.Printf("[input     ] %b\n", input)

	tempered := rightTemper(input, u)
	fmt.Printf("[tempered  ] %b\n", tempered)

	untempered := rightUntemper(tempered, u)
	fmt.Printf("[untempered] %b\n", untempered)

	if untempered != input {
		t.Fail()
	}
}

func TestRightUntemperL(t *testing.T) {
	input := uint32(3294967295)

	fmt.Printf("[input     ] %032b\n", input)

	tempered := rightTemper(input, l)
	fmt.Printf("[tempered  ] %032b\n", tempered)

	untempered := rightUntemper(tempered, l)
	fmt.Printf("[untempered] %032b\n", untempered)

	if untempered != input {
		t.Fail()
	}
}

func TestLeftUntemperSB(t *testing.T) {
	input := uint32(3294967295)

	fmt.Printf("[input     ] %032b\n", input)

	tempered := leftTemper(input, s, b)
	fmt.Printf("[tempered  ] %032b\n", tempered)

	untempered := leftUntemper(tempered, s, b)
	fmt.Printf("[untempered] %032b\n", untempered)

	if untempered != input {
		t.Fail()
	}
}

func TestLeftUntemperTC(tt *testing.T) {
	input := uint32(3294967295)

	fmt.Printf("[input     ] %032b\n", input)

	tempered := leftTemper(input, t, c)
	fmt.Printf("[tempered  ] %032b\n", tempered)

	untempered := leftUntemper(tempered, t, c)
	fmt.Printf("[untempered] %032b\n", untempered)

	if untempered != input {
		tt.Fail()
	}
}

func TestUntemper(t *testing.T) {
	input := uint32(3294967295)

	fmt.Printf("[input     ] %032b\n", input)

	tempered := Temper(input)
	fmt.Printf("[tempered  ] %032b\n", tempered)

	untempered := Untemper(tempered)
	fmt.Printf("[untempered] %032b\n", untempered)

	if untempered != input {
		t.Fail()
	}
}
