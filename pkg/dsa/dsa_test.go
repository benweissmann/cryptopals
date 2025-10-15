package dsa_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/dsa"
)

func TestSign(t *testing.T) {
	data := []byte("abcd")
	keypair := dsa.NewKeypair(dsa.DefaultParams())
	signature := keypair.Sign(data)

	ok, err := keypair.PublicKey().Verify(data, signature)
	if !ok {
		t.Fatal(err)
	}

	badSigS := &dsa.Signature{
		R: signature.R,
		S: (&big.Int{}).Add(signature.S, big.NewInt(1)),
	}
	if ok, _ = keypair.PublicKey().Verify(data, badSigS); ok {
		t.Fatal("Pass with bad S")
	}

	badSigR := &dsa.Signature{
		S: signature.S,
		R: (&big.Int{}).Add(signature.R, big.NewInt(1)),
	}
	if ok, _ = keypair.PublicKey().Verify(data, badSigR); ok {
		t.Fatal("Pass with bad R")
	}

	badDataPrefix := bytes.Join([][]byte{
		{0xde},
		data[1:],
	}, []byte{})
	if ok, _ = keypair.PublicKey().Verify(badDataPrefix, signature); ok {
		t.Fatal("Pass with bad data suffix")
	}

	badDataSuffix := bytes.Join([][]byte{
		data[0 : len(data)-1],
		{0xde},
	}, []byte{})
	if ok, _ = keypair.PublicKey().Verify(badDataSuffix, signature); ok {
		t.Fatal("Pass with bad data suffix")
	}
}
