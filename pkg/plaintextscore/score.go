package plaintextscore

import (
	"math"
	"strings"
)

var englishFreqs = map[rune]float64{
	'A': 0.084966,
	'B': 0.020720,
	'C': 0.045388,
	'D': 0.033844,
	'E': 0.1011607,
	'F': 0.018121,
	'G': 0.024705,
	'H': 0.030034,
	'I': 0.075448,
	'J': 0.001965,
	'K': 0.011016,
	'L': 0.054893,
	'M': 0.030129,
	'N': 0.066544,
	'O': 0.071635,
	'P': 0.031671,
	'Q': 0.001962,
	'R': 0.075809,
	'S': 0.057351,
	'T': 0.069509,
	'U': 0.036308,
	'V': 0.010074,
	'W': 0.012899,
	'X': 0.002902,
	'Y': 0.017779,
	'Z': 0.002722,
	' ': 0.025,
	'_': 0,
}

var maxFreq = englishFreqs['E']

func ScorePlaintextSimple(plaintext string) float64 {
	score := 0.0
	for _, r := range strings.ToUpper(plaintext) {
		chrScore, ok := englishFreqs[r]
		if ok {
			score += chrScore
		} else {
			score -= maxFreq
		}
	}

	return score / (float64(len(plaintext)) * maxFreq)
}

// This seemed interesting, but doesn't work as well as the simple score --
// euclidean distance doesn't work well with high-cardinality inputs
// like this (and the behavior above of actively penalizing non-characters
// is very effective for the plaintexts we're dealing with)
func ScorePlaintextEuclidean(plaintext string) float64 {
	freqs := make(map[rune]int)
	totalFreq := 0

	for _, r := range strings.ToUpper(plaintext) {
		if _, ok := englishFreqs[r]; ok {
			// Valid letter; track the frequency
			freqs[r] = freqs[r] + 1
		} else {
			// invalid; track as _
			freqs['_'] = freqs['_'] + 1
		}

		totalFreq = totalFreq + 1
	}

	if totalFreq == 0 {
		return 0
	}

	normalizedFreqs := make(map[rune]float64, len(englishFreqs))
	for k, v := range freqs {
		normalizedFreqs[k] = float64(v) / float64(totalFreq)
	}

	euclideanBase := 0.0
	for r, englishFreq := range englishFreqs {
		euclideanBase += math.Pow(float64(englishFreq-normalizedFreqs[r]), 2)
	}

	euclideanDistance := math.Sqrt(euclideanBase)

	return (math.Sqrt(2) - euclideanDistance) / math.Sqrt(2)
}
