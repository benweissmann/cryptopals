package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/cbc"
	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/ctr"
	"github.com/benweissmann/cryptopals/pkg/padding"
)

func oracleCtr(p string) int {
	// format request
	formattedRequest := fmt.Sprintf(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
%s`, len(p), p)

	// compress
	var compressedRequest bytes.Buffer
	w := zlib.NewWriter(&compressedRequest)
	w.Write([]byte(formattedRequest))
	w.Close()

	// encrypt
	cipher, err := aes.NewCipher(convert.RandomKey())
	if err != nil {
		panic(err)
	}

	ctrCrypt := ctr.NewCTRCrypter(cipher, ctr.RandomIV())
	encrypted := make([]byte, compressedRequest.Len())
	ctrCrypt.CryptBlocks(encrypted, compressedRequest.Bytes())

	return len(encrypted)
}

var b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
var targetLength = 44

func part1() string {
	sessionId := ""

	for len(sessionId) < targetLength {
		// See what pair of characters compresses best. We use 2 characters to avoid
		// false-positives: the difference between two matching characters vs. not
		// is more significant than with one character

		minLen := 99999
		bestPair := "!!"

		baseStr := "sessionId=" + sessionId

		for _, c1 := range b64chars {
			for _, c2 := range b64chars {
				score := oracleCtr(baseStr + string(c1) + string(c2))

				if score < minLen {
					minLen = score
					bestPair = string(c1) + string(c2)
				}
			}
		}

		sessionId += bestPair
		fmt.Println(sessionId)
	}

	return sessionId
}

func oracleCbc(p string) int {
	// format request
	formattedRequest := fmt.Sprintf(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
%s`, len(p), p)

	// compress
	var compressedRequest bytes.Buffer
	w := zlib.NewWriter(&compressedRequest)
	w.Write([]byte(formattedRequest))
	w.Close()

	// pad
	padded := padding.PKCS7Pad(compressedRequest.Bytes(), aes.BlockSize)

	// encrypt
	cipher, err := aes.NewCipher(convert.RandomKey())
	if err != nil {
		panic(err)
	}

	ctrCrypt := cbc.NewCBCEncrypter(cipher, convert.RandomKey())
	encrypted := make([]byte, len(padded))
	ctrCrypt.CryptBlocks(encrypted, padded)

	return len(encrypted)
}

// uncompressible junk. Can't appear in the formatted requrest
var junkChars = "!@#$%^&*(){}[]|\\"

func part2() string {
	sessionId := ""

	for len(sessionId) < targetLength {
		// See what pair of characters compresses best. We use 2 characters to avoid
		// false-positives: the difference between two matching characters vs. not
		// is more significant than with one character

		minLen := 99999
		bestPair := "!!"

		baseStr := "sessionId=" + sessionId

		for _, c1 := range b64chars {
			for _, c2 := range b64chars {
				// With a CBC oracle, we're not getting an accurate picture of
				// compressions because when we hit the right value, the padding just
				// adds back the bytes we "won".
				//
				// So we need a padding oracle: we adjust the score by how many bytes
				// of random, uncompressible junk we can add before it makes it longer
				baseScore := oracleCbc(baseStr + string(c1) + string(c2))

				junk := ""
				for _, jc := range junkChars {
					junk += string(jc)
					scoreWJunk := oracleCbc(baseStr + string(c1) + string(c2) + junk)
					if scoreWJunk > baseScore {
						// we've added enough junk to overflow the block
						break
					}
				}

				score := baseScore - len(junk)

				if score < minLen {
					minLen = score
					bestPair = string(c1) + string(c2)
				}
			}
		}

		sessionId += bestPair
		fmt.Println(sessionId)
	}

	return sessionId
}

func main() {
	part1Sln := part1()

	if part1Sln != "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		panic("Part 1 failed")
	}

	part2Sln := part2()

	if part2Sln != "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		panic("Part 2 failed")
	}
}
