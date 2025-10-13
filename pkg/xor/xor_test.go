package xor_test

import (
	"encoding/hex"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

func TestXor(t *testing.T) {
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"

	outBytes := xor.Xor(convert.MustParseHex(in1), convert.MustParseHex(in2))

	out := hex.EncodeToString((outBytes))
	want := "746865206b696420646f6e277420706c6179"
	if want != out {
		t.Fatalf("Got %s; want %s", out, want)
	}
}
