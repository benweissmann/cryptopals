package rsa_test

import (
	"bytes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/rsa"
)

func TestPadUnpad(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	paddedData := rsa.PadHashForSignature(data, 1024)

	if len(paddedData) != 1024/8 {
		t.Fatalf("Bad data length: %d", len(paddedData))
	}

	if !bytes.HasPrefix(paddedData, []byte{0x00, 0x01}) {
		t.Fatalf("Bad prefix: %x", paddedData[0:2])
	}

	if !bytes.HasSuffix(paddedData, data) {
		t.Fatalf("Bad suffix: %x", paddedData[len(paddedData)-3:])
	}

	unpadded, err := rsa.UnpadHash(paddedData)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(unpadded, data) {
		t.Fatalf("Bad unpadding result: %x", unpadded)
	}
}

func TestSign(t *testing.T) {
	data := []byte("abcd")
	keypair := rsa.NewKeypair()
	signature := keypair.Sign(data)

	ok, err := keypair.PublicKey().SloppyVerify(data, signature)
	if !ok {
		t.Fatal(err)
	}

	badSigPrefix := bytes.Join([][]byte{
		{0xde},
		signature[1:],
	}, []byte{})
	if ok, _ = keypair.PublicKey().SloppyVerify(data, badSigPrefix); ok {
		t.Fatal("Pass with bad prefix")
	}

	badSigSuffix := bytes.Join([][]byte{
		signature[0 : len(signature)-1],
		{0xde},
	}, []byte{})
	if ok, _ = keypair.PublicKey().SloppyVerify(data, badSigSuffix); ok {
		t.Fatal("Pass with bad suffix")
	}

	badDataPrefix := bytes.Join([][]byte{
		{0xde},
		data[1:],
	}, []byte{})
	if ok, _ = keypair.PublicKey().SloppyVerify(badDataPrefix, signature); ok {
		t.Fatal("Pass with bad data suffix")
	}

	badDataSuffix := bytes.Join([][]byte{
		data[0 : len(data)-1],
		{0xde},
	}, []byte{})
	if ok, _ = keypair.PublicKey().SloppyVerify(badDataSuffix, signature); ok {
		t.Fatal("Pass with bad data suffix")
	}
}
