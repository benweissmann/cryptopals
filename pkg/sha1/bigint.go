package sha1

import "math/big"

func HashToBigInt(b []byte) *big.Int {
	sha := New()
	_, err := sha.Write(b)
	if err != nil {
		panic(err)
	}

	return (&big.Int{}).SetBytes(sha.Sum([]byte{}))
}
