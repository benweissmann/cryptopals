package dsa

import "testing"

func TestRecoverFromK(t *testing.T) {
	origKeypair := NewKeypair(DefaultParams())

	msg := []byte("hello world")
	k := origKeypair.GenerateK()

	sig := origKeypair.SignWithGivenK(msg, k)

	recoveredKeypair := RecoverPrivateKeyFromK(k, msg, sig, origKeypair.PublicKey())

	if recoveredKeypair.X.Cmp(origKeypair.X) != 0 {
		t.Fatalf("Mismatched X. Got: %x Expected: %x", recoveredKeypair.X, origKeypair.X)
	}
}
