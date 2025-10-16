package bleichenbacheroracle

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
)

type Range struct {
	Min *big.Int
	Max *big.Int
}

func (r Range) SingleValue() *big.Int {
	if r.Min.Cmp(r.Max) == 0 {
		return r.Min
	}

	return nil
}

func (r Range) Cmp(r2 Range) int {
	minCmp := r.Min.Cmp(r2.Min)

	if minCmp == 0 {
		return r.Max.Cmp(r2.Max)
	} else {
		return minCmp
	}
}

func (r Range) String() string {
	return fmt.Sprintf("%d - %d", r.Min, r.Max)
}

type RangeSet struct {
	Ranges []Range
}

func NewRange(min *big.Int, max *big.Int) Range {
	if lt(max, min) {
		panic(fmt.Sprintf("Backwards range. Min: %d Max: %d", min, max))
	}

	return Range{
		Min: min,
		Max: max,
	}
}

// Adds a range to the range set. If it overlaps with any existing range,
// extends that range to include the new range. Otherwise, adds it as a new
// disjoint range
func (s *RangeSet) Add(newR Range) {
	for i, r := range s.Ranges {
		if !(lt(newR.Max, r.Min) || gt(newR.Min, r.Max)) {
			// overlap
			s.Ranges[i] = NewRange(
				min(r.Min, newR.Min),
				max(r.Max, newR.Max),
			)
			return
		}
	}

	// No overlaps found
	s.Ranges = append(s.Ranges, newR)
}

func (s *RangeSet) Size() int {
	return len(s.Ranges)
}

func (s *RangeSet) SingleValue() *big.Int {
	if s.Size() != 1 {
		return nil
	}

	return s.Ranges[0].SingleValue()
}

func (s *RangeSet) SortedRanges() []Range {
	sortedRanges := slices.Clone(s.Ranges)
	slices.SortFunc(sortedRanges, func(r1, r2 Range) int {
		return r1.Cmp(r2)
	})

	return sortedRanges
}

func (s *RangeSet) String() string {
	strs := make([]string, len(s.Ranges))
	for i, r := range s.SortedRanges() {
		strs[i] = r.String()
	}

	return strings.Join(strs, ", ")
}

func (s *RangeSet) Eq(s2 *RangeSet) bool {
	if s.Size() != s2.Size() {
		return false
	}

	ranges1 := s.SortedRanges()
	ranges2 := s2.SortedRanges()

	for i, r1 := range ranges1 {
		r2 := ranges2[i]

		if r1.Cmp(r2) != 0 {
			return false
		}
	}

	return true
}
