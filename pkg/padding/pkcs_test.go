package padding_test

import (
	"bytes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/padding"
)

func TestPadUnpad(t *testing.T) {
	in1 := []byte{1, 2, 3}
	out1 := []byte{1, 2, 3, 1}

	if !bytes.Equal(padding.PKCS7Pad(in1, 4), out1) {
		t.Fatalf("Padding failed: got %v; expected %v", padding.PKCS7Pad(in1, 4), out1)
	}

	if !bytes.Equal(padding.PKCS7Unpad(out1), in1) {
		t.Fatalf("Unpadding failed: got %v; expected %v", padding.PKCS7Unpad(out1), in1)
	}

	in2 := []byte{1, 2, 1, 2}
	out2 := []byte{1, 2, 1, 2, 4, 4, 4, 4}

	if !bytes.Equal(padding.PKCS7Pad(in2, 4), out2) {
		t.Fatalf("Padding failed: got %v; expected %v", padding.PKCS7Pad(in2, 4), out2)
	}

	if !bytes.Equal(padding.PKCS7Unpad(out2), in2) {
		t.Fatalf("Unpadding failed: got %v; expected %v", padding.PKCS7Unpad(out2), in2)
	}
}

func TestVerify(t *testing.T) {
	valid1 := []byte{1, 2, 3, 1}
	expected1 := []byte{1, 2, 3}

	output, ok := padding.VerifyPKCSPadding(valid1)
	if !ok {
		t.Fatalf("Failed verification: %v", valid1)
	}
	if !bytes.Equal(output, expected1) {
		t.Fatalf("Unpad failed: got %v, expected %v", output, expected1)
	}

	valid2 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	expected2 := []byte("ICE ICE BABY")

	output, ok = padding.VerifyPKCSPadding(valid2)
	if !ok {
		t.Fatalf("Failed verification: %v", valid2)
	}
	if !bytes.Equal(output, expected2) {
		t.Fatalf("Unpad failed: got %v, expected %v", output, expected2)
	}

	_, ok = padding.VerifyPKCSPadding([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	if ok {
		t.Fatalf("Did not detect bad padding (case 1)")
	}

	_, ok = padding.VerifyPKCSPadding([]byte("ICE ICE BABY\x01\x02\x03\x04"))
	if ok {
		t.Fatalf("Did not detect bad padding (case 2)")
	}
}
