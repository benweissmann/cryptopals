package convert

import (
	"fmt"
	"math/big"
)

func ParseHexToBigInt(str string) *big.Int {
	i, ok := (&big.Int{}).SetString(str, 16)
	if !ok {
		panic(fmt.Sprintf("Failed to parse hex integer: %s", str))
	}

	return i
}

func ParseDecimalToBigInt(str string) *big.Int {
	i, ok := (&big.Int{}).SetString(str, 10)
	if !ok {
		panic(fmt.Sprintf("Failed to parse decimal integer: %s", str))
	}

	return i
}

func ParseBase64ToBigInt(str string) *big.Int {
	i := &big.Int{}
	i.SetBytes(MustParseBase64(str))

	return i
}
