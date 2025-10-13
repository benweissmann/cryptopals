package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"time"
)

func writeError(msg string, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(400)

	w.Write([]byte(msg))
}

func writeSuccess(msg string, w http.ResponseWriter) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(200)

	w.Write([]byte(msg))
}

// // This makes the challenge much easier -- gives erors of 30 microseconds or
// // so, vs. a couple milliseconds
// func preciseSleep(t time.Duration) {
// 	start := time.Now()

// 	for {
// 		if time.Now().Sub(start) >= t {
// 			return
// 		}
// 	}
// }

func insecureByteEquals(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range len(a) {
		if a[i] != b[i] {
			return false
		}

		time.Sleep(5 * time.Millisecond)
	}

	return true
}

func main() {
	cachedHashes := map[string][]byte{}

	getCorrectHash := func(file string) []byte {
		cached, ok := cachedHashes[file]
		if ok {
			return cached
		}

		macHasher := hmac.New(sha1.New, []byte("YELLOW SUBMARINE"))
		macHasher.Write([]byte(file))
		correctSignature := macHasher.Sum([]byte{})

		cachedHashes[file] = correctSignature

		return correctSignature
	}

	getFile := func(w http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()

		file := query.Get("file")
		if file == "" {
			writeError("Missing file name", w)
			return
		}

		signatureHex := query.Get("signature")
		if signatureHex == "" {
			writeError("Missing signature", w)
			return
		}

		signature, err := hex.DecodeString(signatureHex)
		if err != nil {
			writeError("Bad hex encoding", w)
			return
		}

		if !insecureByteEquals([]byte(signature), getCorrectHash(file)) {
			writeError("Bad signature", w)
			return
		}

		writeSuccess("Here's the file", w)
	}

	http.HandleFunc("/test", getFile)

	http.ListenAndServe(":8000", nil)
}
