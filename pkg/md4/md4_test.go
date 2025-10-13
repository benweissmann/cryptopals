package md4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

var rfc1320Cases = []struct {
	in     string
	outHex string
}{
	{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
	{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
	{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
	{"message digest", "d9130a8164549fe818874806e1c7014b"},
	{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
	{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
	{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
}

func TestRFC1320Vectors(t *testing.T) {
	for _, tt := range rfc1320Cases {
		t.Run(fmt.Sprintf("md4(%s) = %s", tt.in, tt.outHex), func(t *testing.T) {
			hash := New()
			_, err := hash.Write([]byte(tt.in))
			if err != nil {
				t.Fatal(err.Error())
			}

			actual := hex.EncodeToString(hash.Sum([]byte{}))

			if actual != tt.outHex {
				t.Fatalf("Got %s - Expected %s", actual, tt.outHex)
			}
		})
	}
}

func TestResume(t *testing.T) {
	hash1 := New()

	base := []byte("The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. ")
	_, err := hash1.Write(base)
	if err != nil {
		t.Fatal(err)
	}

	intermediateInput := []byte{}
	intermediateInput = append(intermediateInput, base...)
	intermediateInput = append(intermediateInput, Padding(uint64(len(base)))...)

	intermediate := hash1.Sum([]byte{})

	hash2 := Resume(intermediate, uint64(len(intermediateInput)))

	_, err = hash2.Write([]byte("Some extra data!"))
	if err != nil {
		t.Fatal(err)
	}

	out1 := hash2.Sum([]byte{})

	hash1.Write(Padding(uint64(len(base))))

	hash1.Write([]byte("Some extra data!"))
	out2 := hash1.Sum([]byte{})

	if !bytes.Equal(out1, out2) {
		t.Fatalf("out1 %x - out2 %x", out1, out2)
	}
}
