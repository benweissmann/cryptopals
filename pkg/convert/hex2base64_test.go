package convert_test

import (
	"testing"

	"github.com/benweissmann/cryptopals/pkg/convert"
)

func TestHex2Base64(t *testing.T) {
	in1 := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	out1, err1 := convert.Hex2base64(in1)

	if err1 != nil {
		t.Fatal(err1.Error())
	}

	want1 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if out1 != want1 {
		t.Fatalf("Wanted %s; got %s", want1, out1)
	}
}
