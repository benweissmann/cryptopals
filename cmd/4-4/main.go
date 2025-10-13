package main

import (
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/sha1"
)

func main() {
	sha := sha1.New()

	fmt.Println(sha.Inspect())

	sha.Write([]byte("a"))

	fmt.Println(sha.Inspect())

	sha.Write([]byte("bc "))

	fmt.Println(sha.Inspect())

	sha.Write([]byte("The quick brown fox jumped over the lazy dog! The quick brown fox jumped over the lazy dog!"))

	fmt.Println(sha.Inspect())

	// resume from abc
	fmt.Println()

	sha2 := sha1.Resume(convert.MustParseHex("67901ba1505950fa20a688818dd292b8db9dae3a"), 128)
	fmt.Println(sha2.Inspect())

	sha2.Write([]byte(" Some extra!!!"))
	fmt.Println(sha2.Inspect())

	// should match (original) + (padding) + ( Some extra!!!)
	sha.Write(sha1.Padding(uint64(len("abc The quick brown fox jumped over the lazy dog! The quick brown fox jumped over the lazy dog!"))))
	sha.Write([]byte(" Some extra!!!"))

	fmt.Println(sha.Inspect())
}
