package plaintextscore_test

import (
	"testing"

	"github.com/benweissmann/cryptopals/pkg/plaintextscore"
)

func TestScorePlaintextSimple(t *testing.T) {
	goodScore := plaintextscore.ScorePlaintextSimple("The quick brown fox jumped over the lazy dog")

	badInputs := []string{
		"8983y894ryaoi4ryo38oa",
		"zzzzzzzzzzzzz",
		"The!z$qU&ickB$@!rown",
		"U+)Ex�NSqhe/]PuSE7Nr;Rw;OUqeas",
	}

	for _, badInput := range badInputs {
		badScore := plaintextscore.ScorePlaintextSimple(badInput)

		if badScore > goodScore {
			t.Fatalf("Bad text %s scored higher (%f) than good text (%f)", badInput, badScore, goodScore)
		}
	}
}

func TestScorePlaintextEuclidean(t *testing.T) {
	goodScore := plaintextscore.ScorePlaintextEuclidean("The quick brown fox jumped over the lazy dog")

	badInputs := []string{
		"8983y894ryaoi4ryo38oa",
		"zzzzzzzzzzzzz",
		"The!z$qU&ickB$@!rown",
		"U+)Ex�NSqhe/]PuSE7Nr;Rw;OUqeas",
	}

	for _, badInput := range badInputs {
		badScore := plaintextscore.ScorePlaintextEuclidean(badInput)

		if badScore > goodScore {
			t.Fatalf("Bad text %s scored higher (%f) than good text (%f)", badInput, badScore, goodScore)
		}
	}
}
