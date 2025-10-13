package srp

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/dh"
)

const g = 2
const k = 3

var n = dh.DefaultP

func hashToInt(hash []byte) *big.Int {
	i := big.NewInt(0)
	i.SetBytes(hash)
	return i
}

func computeX(password string, salt []byte) *big.Int {
	xHHash := sha256.New()
	xHHash.Write(salt)
	xHHash.Write([]byte(password))
	xH := xHHash.Sum(nil)
	return hashToInt(xH)
}

func computeU(aPub *big.Int, bPub *big.Int) *big.Int {
	uH := sha256.New()
	_, err := uH.Write(aPub.Bytes())
	if err != nil {
		panic(err)
	}

	_, err = uH.Write(bPub.Bytes())
	if err != nil {
		panic(err)
	}

	return hashToInt(uH.Sum(nil))
}

func ComputeK(s *big.Int) []byte {
	kH := sha256.New()
	_, err := kH.Write(s.Bytes())
	if err != nil {
		panic(err)
	}

	return kH.Sum(nil)
}

func ComputeFinalHmac(k []byte, salt []byte) []byte {
	finalHmac := hmac.New(sha256.New, salt)
	_, err := finalHmac.Write(k)
	if err != nil {
		panic(err)
	}

	return finalHmac.Sum(nil)
}
