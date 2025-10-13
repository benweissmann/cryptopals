package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func RequestFile(sig []byte) (ok bool, contentOrError string, timing time.Duration) {
	url := fmt.Sprintf("http://localhost:8000/test?file=foo&signature=%x", sig)

	start := time.Now()
	resp, err := http.Get(url)
	end := time.Now()
	duration := end.Sub(start)

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

	return resp.StatusCode == http.StatusOK, string(body), duration
}

func crackSig() string {
	crackedSig := make([]byte, 20)

	for i := 0; i < 20; i++ {
		// crack byte i

		var slowestByte byte
		var slowestTime time.Duration

		for j := 0; j < 256; j++ {
			testSig := make([]byte, 20)
			copy(testSig, crackedSig)
			testSig[i] = byte(j)

			ok, content, timing := RequestFile(testSig)
			if ok {
				fmt.Printf("Cracked signature: %x\n", testSig)
				return content
			}

			if timing > slowestTime {
				slowestByte = byte(j)
				slowestTime = timing
			}
		}

		crackedSig[i] = slowestByte
		fmt.Printf("%x\n", crackedSig)
	}

	panic("Could not crack signature")
}

func main() {
	fmt.Println(crackSig())
}
