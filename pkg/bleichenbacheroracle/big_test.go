package bleichenbacheroracle

import (
	"math/big"
	"testing"
)

func TestLt(t *testing.T) {
	if lt(big.NewInt(1), big.NewInt(2)) != true {
		t.Fatal("Failed 1<2")
	}

	if lt(big.NewInt(1), big.NewInt(1)) != false {
		t.Fatal("Failed 1<1")
	}

	if lt(big.NewInt(2), big.NewInt(1)) != false {
		t.Fatal("Failed 2<1")
	}
}

func TestLte(t *testing.T) {
	if lte(big.NewInt(1), big.NewInt(2)) != true {
		t.Fatal("Failed 1<=2")
	}

	if lte(big.NewInt(1), big.NewInt(1)) != true {
		t.Fatal("Failed 1<=1")
	}

	if lte(big.NewInt(2), big.NewInt(1)) != false {
		t.Fatal("Failed 2<=1")
	}
}

func TestGt(t *testing.T) {
	if gt(big.NewInt(1), big.NewInt(2)) != false {
		t.Fatal("Failed 1>2")
	}

	if gt(big.NewInt(1), big.NewInt(1)) != false {
		t.Fatal("Failed 1>1")
	}

	if gt(big.NewInt(2), big.NewInt(1)) != true {
		t.Fatal("Failed 2>1")
	}
}

func TestFloorDiv(t *testing.T) {
	if floorDiv(big.NewInt(6), big.NewInt(2)).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("Failed 6/2")
	}

	if floorDiv(big.NewInt(7), big.NewInt(2)).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("Failed 7/2")
	}
}

func TestCeilDiv(t *testing.T) {
	if ceilDiv(big.NewInt(6), big.NewInt(2)).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("Failed 6/2")
	}

	if ceilDiv(big.NewInt(7), big.NewInt(2)).Cmp(big.NewInt(4)) != 0 {
		t.Fatal("Failed 7/2")
	}
}

func TestMin(t *testing.T) {
	if min(big.NewInt(10), big.NewInt(20)).Cmp(big.NewInt(10)) != 0 {
		t.Fatal("failed min(10, 20)")
	}

	if min(big.NewInt(10), big.NewInt(5)).Cmp(big.NewInt(5)) != 0 {
		t.Fatal("failed min(10, 5)")
	}

	if min(big.NewInt(5), big.NewInt(5)).Cmp(big.NewInt(5)) != 0 {
		t.Fatal("failed min(5, 5)")
	}
}

func TestMax(t *testing.T) {
	if max(big.NewInt(10), big.NewInt(20)).Cmp(big.NewInt(20)) != 0 {
		t.Fatal("failed max(10, 20)")
	}

	if max(big.NewInt(10), big.NewInt(5)).Cmp(big.NewInt(10)) != 0 {
		t.Fatal("failed max(10, 5)")
	}

	if max(big.NewInt(5), big.NewInt(5)).Cmp(big.NewInt(5)) != 0 {
		t.Fatal("failed max(5, 5)")
	}
}
