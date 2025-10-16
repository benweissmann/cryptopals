package bleichenbacheroracle

import (
	"math/big"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/rsa"
)

func TestPKCSPad(t *testing.T) {
	padded := PKCS15Pad(
		[]byte{0x01, 0x02, 0x03},
		512,
	)

	if len(padded) != 512/8 {
		t.Fatalf("Got length %d, expected %d", len(padded), 512/8)
	}

	if padded[0] != 0 {
		t.Fatalf("Bad first byte: %x", padded[0])
	}

	if padded[1] != 2 {
		t.Fatalf("Bad second byte: %x", padded[0])
	}

	if padded[60] != 0 {
		t.Fatalf("Bad separator: %x", padded[61])
	}

	if padded[61] != 1 {
		t.Fatalf("Bad first data: %x", padded[61])
	}

	if padded[62] != 2 {
		t.Fatalf("Bad second data: %x", padded[62])
	}

	if padded[63] != 3 {
		t.Fatalf("Bad third data: %x", padded[63])
	}
}

func TestPKCSPadNoRandomZero(t *testing.T) {
	padded := PKCS15Pad(
		[]byte{0x01, 0x02, 0x03},
		// long so we have a high chance of 0s
		8000000,
	)

	for i, b := range padded[1 : len(padded)-4] {
		if b == 0 {
			t.Fatalf("Found 0 at position %d", i)
		}
	}

	if len(padded) != 1000000 {
		t.Fatalf("Got length %d, expected %d", len(padded), 1000000)
	}

	if padded[0] != 0 {
		t.Fatalf("Bad first byte: %x", padded[0])
	}

	if padded[1000000-4] != 0 {
		t.Fatalf("Bad separator: %x", padded[1000000-4])
	}

}

func TestOracle(t *testing.T) {
	goodMsg := PKCS15Pad(
		[]byte{0x01, 0x02, 0x03},
		512,
	)
	keypair := rsa.NewKeypairWithParams(512, rsa.DefaultE)

	if Oracle(keypair, keypair.PublicKey().Encrypt((&big.Int{}).SetBytes(goodMsg))) == false {
		t.Fatalf("Good ciphertext returned false")
	}

	badMsg1 := make([]byte, len(goodMsg))
	copy(badMsg1, goodMsg)
	badMsg1[0] = 0x02

	if Oracle(keypair, keypair.PublicKey().Encrypt((&big.Int{}).SetBytes(badMsg1))) == true {
		t.Fatalf("Bad ciphertext 1 returned true")
	}

	badMsg2 := make([]byte, len(goodMsg))
	copy(badMsg2, goodMsg)
	badMsg2[1] = 0x00
	if Oracle(keypair, keypair.PublicKey().Encrypt((&big.Int{}).SetBytes(badMsg1))) == true {
		t.Fatalf("Bad ciphertext 2 returned true")
	}

}
