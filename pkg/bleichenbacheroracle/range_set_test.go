package bleichenbacheroracle

import (
	"fmt"
	"math/big"
	"testing"
)

func constructTestRangeSet(intRanges [][2]int) *RangeSet {
	ranges := make([]Range, len(intRanges))
	for i, pair := range intRanges {
		ranges[i] = NewRange(big.NewInt(int64(pair[0])), big.NewInt(int64(pair[1])))
	}

	return &RangeSet{
		Ranges: ranges,
	}
}

func TestRangeSet(t *testing.T) {
	rs := &RangeSet{}

	rs.Add(NewRange(big.NewInt(5), big.NewInt(10)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{5, 10},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// add above
	rs.Add(NewRange(big.NewInt(105), big.NewInt(110)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{105, 110},
		{5, 10},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// extend max
	rs.Add(NewRange(big.NewInt(9), big.NewInt(11)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{105, 110},
		{5, 11},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// extend max, exact match
	rs.Add(NewRange(big.NewInt(11), big.NewInt(13)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{105, 110},
		{5, 13},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// extend min
	rs.Add(NewRange(big.NewInt(102), big.NewInt(107)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{102, 110},
		{5, 13},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// extend min, exact match
	rs.Add(NewRange(big.NewInt(101), big.NewInt(102)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{101, 110},
		{5, 13},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// add in the middle
	rs.Add(NewRange(big.NewInt(50), big.NewInt(60)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{101, 110},
		{5, 13},
		{50, 60},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}

	// add below
	rs.Add(NewRange(big.NewInt(1), big.NewInt(2)))
	fmt.Println(rs)

	if !rs.Eq(constructTestRangeSet([][2]int{
		{1, 2},
		{101, 110},
		{5, 13},
		{50, 60},
	})) {
		t.Fatalf("Wrong range set: %s", rs)
	}
}

func TestRangeSetEq(t *testing.T) {
	if !(constructTestRangeSet([][2]int{
		{3, 4},
		{1, 2},
	})).Eq(constructTestRangeSet([][2]int{
		{1, 2}, {3, 4},
	})) {
		t.Fatal("Failed ordering test")
	}

	if !(constructTestRangeSet([][2]int{
		{1, 2},
	})).Eq(constructTestRangeSet([][2]int{
		{1, 2},
	})) {
		t.Fatal("Failed single test")
	}

	if !(constructTestRangeSet([][2]int{
		{1, 1},
	})).Eq(constructTestRangeSet([][2]int{
		{1, 1},
	})) {
		t.Fatal("Failed one test")
	}

	if !(constructTestRangeSet([][2]int{})).Eq(constructTestRangeSet([][2]int{})) {
		t.Fatal("Failed emptu test")
	}

	if (constructTestRangeSet([][2]int{
		{3, 4},
		{1, 2},
	})).Eq(constructTestRangeSet([][2]int{
		{1, 2}, {3, 5},
	})) {
		t.Fatal("Failed max mismatch test")
	}

	if (constructTestRangeSet([][2]int{
		{3, 4},
		{1, 2},
	})).Eq(constructTestRangeSet([][2]int{
		{0, 2}, {3, 4},
	})) {
		t.Fatal("Failed min mismatch test")
	}

	if (constructTestRangeSet([][2]int{
		{1, 2},
		{3, 4},
	})).Eq(constructTestRangeSet([][2]int{
		{1, 2},
	})) {
		t.Fatal("Failed mismatched length test")
	}
}

func TestSingleValue(t *testing.T) {
	if (constructTestRangeSet([][2]int{
		{2, 2},
	})).SingleValue().Cmp(two) != 0 {
		t.Fatal("Failed single value test")
	}

	if (constructTestRangeSet([][2]int{
		{1, 1},
		{2, 2},
	})).SingleValue() != nil {
		t.Fatal("Failed two range test")
	}

	if (constructTestRangeSet([][2]int{
		{1, 2},
	})).SingleValue() != nil {
		t.Fatal("Failed single range test")
	}

	if (constructTestRangeSet([][2]int{})).SingleValue() != nil {
		t.Fatal("Failed empty test")
	}
}
