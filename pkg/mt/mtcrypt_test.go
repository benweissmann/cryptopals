package mt_test

import (
	"bytes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/mt"
)

func TestMtCrypt(t *testing.T) {
	crypter := mt.NewMTCrypter(1234)

	input := []byte("HELLO WORLD")
	encrypted := make([]byte, len(input))

	crypter.CryptBlocks(encrypted, input)

	output := make([]byte, len(encrypted))
	crypter2 := mt.NewMTCrypter(1234)

	crypter2.CryptBlocks(output, encrypted)

	if !bytes.Equal(input, output) {
		t.Fail()
	}

}
