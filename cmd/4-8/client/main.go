package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	httpstat "github.com/tcnksm/go-httpstat"
)

func RequestFile(sig []byte) (ok bool, contentOrError string, timing time.Duration) {
	url := fmt.Sprintf("http://localhost:8000/test?file=foo&signature=%x", sig)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err.Error())
	}

	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err.Error())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err.Error())
	}

	err = resp.Body.Close()
	if err != nil {
		panic(err.Error())
	}

	return resp.StatusCode == http.StatusOK, string(body), result.ServerProcessing
}

const ROUNDS = 10
const ALLOWED_JITTER = time.Microsecond * 2000

func crackSig() string {
	crackedSig := make([]byte, 20)

	// Threshold between the slowest measurement and the second-slowest measurement.
	// We set this for the first byte (which has cleanest timing), and then use
	// it for future bytes to determine if our reading was clean enough to use
	thresholdMicros := int64(-1)

	for i := 0; i < 20; i++ {
		// crack byte i

		// Store 10 samples of how long it takes to verify each possible byte.
		// We do this round-robin rather than one-byte-at-a-time to mitigate
		// temporary slow-downs. For each possible byte, store its fastest
		// timing (which is the one that should have the least noise)
		var fastestTimes [256]time.Duration

		for round := 0; round < 10; round++ {
			for j := 0; j < 256; j++ {
				testSig := make([]byte, 20)
				copy(testSig, crackedSig)
				testSig[i] = byte(j)

				ok, content, timing := RequestFile(testSig)
				if ok {
					fmt.Printf("Cracked signature: %x\n", testSig)
					return content
				}

				if round == 0 || fastestTimes[j] > timing {
					fastestTimes[j] = timing
				}
			}
		}

		// compute the slowest and second-slowest timing
		var slowestTiming time.Duration
		var slowestTimingByte byte
		var secondSlowestTiming time.Duration

		for j := 0; j < 256; j++ {
			if fastestTimes[j] > slowestTiming {
				secondSlowestTiming = slowestTiming

				slowestTiming = fastestTimes[j]
				slowestTimingByte = byte(j)
			} else if fastestTimes[j] > secondSlowestTiming {
				secondSlowestTiming = fastestTimes[j]
			}
		}

		// for the first byte: accept our result (it should be pretty clean) and
		// use the difference to set our threshold going forward
		if i == 0 {
			crackedSig[i] = slowestTimingByte
			thresholdMicros = slowestTiming.Microseconds() - secondSlowestTiming.Microseconds() - ALLOWED_JITTER.Microseconds()

			fmt.Printf("%x\n", crackedSig)
			fmt.Printf("  Set threshold: %d microseconds\n", thresholdMicros)
		} else {
			// For future bytes, see if the difference between slowest and second-slowest
			// roughly matches the reading from the first byte. If not, our reading was
			// too noisy; try again
			if slowestTiming.Microseconds()-secondSlowestTiming.Microseconds() > thresholdMicros {
				crackedSig[i] = slowestTimingByte
				fmt.Printf("%x\n  Slowest %d vs second slowest %d: difference %d\n",
					crackedSig,
					slowestTiming.Microseconds(),
					secondSlowestTiming.Microseconds(),
					slowestTiming.Microseconds()-secondSlowestTiming.Microseconds(),
				)
			} else {
				fmt.Printf("Difference too close, retrying: %d vs %d\n", slowestTiming.Microseconds(), secondSlowestTiming.Microseconds())
				i--
			}
		}

	}

	panic("Could not crack signature")
}

func main() {
	fmt.Println(crackSig())
}

// 274b7c4d98605fcf739a0bf9237551623f410000
// 274b7c4d98605fcf739a0bf9237551623f415fb8
