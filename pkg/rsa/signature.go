package rsa

import (
	"bytes"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/benweissmann/cryptopals/pkg/sha1"
)

func PadHashForSignature(hash []byte, padLenBits int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(hash)
	})

	asn1Hash, err := b.Bytes()
	if err != nil {
		panic(err)
	}

	paddingLenBytes := (padLenBits / 8) - len(asn1Hash)
	ffByteCount := paddingLenBytes - 3
	if ffByteCount < 1 {
		panic("nout enough space for padding")
	}

	return bytes.Join([][]byte{
		{0x00, 0x01},
		bytes.Repeat([]byte{0xff}, ffByteCount),
		{0x00},
		asn1Hash,
	}, []byte{})
}

func (k *Keypair) Sign(message []byte) []byte {
	paddedData := PadHashForSignature(Sha1HashForSignature(message), KEY_SIZE)

	dataInt := (&big.Int{}).SetBytes(paddedData)
	signedInt := k.Decrypt(dataInt)

	return signedInt.FillBytes(make([]byte, KEY_SIZE/8))
}

func UnpadHash(paddedData []byte) ([]byte, error) {
	if !bytes.HasPrefix(paddedData, []byte{0x00, 0x01, 0xff}) {
		return nil, fmt.Errorf("Invalid prefix: %x", paddedData[0:2])
	}

	i := 3
	for ; i < len(paddedData); i++ {
		if paddedData[i] == 0x00 {
			// end of padding
			break
		}

		if paddedData[i] == 0xff {
			// valid padding
			continue
		}

		return nil, fmt.Errorf("Invalid padding at byte %d: %x", i, paddedData[i])
	}

	asnData := cryptobyte.String(paddedData[i+1:])
	var (
		data, inner cryptobyte.String
	)

	if !asnData.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("Error reading sequence")
	}

	if !inner.ReadASN1(&data, asn1.OCTET_STRING) {
		return nil, fmt.Errorf("Error reading octet string")
	}

	return []byte(data), nil
}

func (p *PublicKey) SloppyVerify(message []byte, sig []byte) (bool, error) {
	correctHash := Sha1HashForSignature(message)

	sigInt := (&big.Int{}).SetBytes(sig)
	paddedHashInt := p.Encrypt(sigInt)
	paddedHash := paddedHashInt.FillBytes(make([]byte, KEY_SIZE/8))

	fmt.Printf("Verifying: %x\n", paddedHash)

	givenHash, err := UnpadHash(paddedHash)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(givenHash, correctHash) {
		return false, fmt.Errorf("Mismatched signature:\nGot     : %x\nExpected: %x", givenHash, correctHash)
	}

	return true, nil
}

func Sha1HashForSignature(message []byte) []byte {
	hash := sha1.New()
	_, err := hash.Write(message)
	if err != nil {
		panic(err)
	}

	return hash.Sum([]byte{})
}
