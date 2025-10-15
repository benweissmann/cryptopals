package convert

import (
	"fmt"
	"math/big"
)

func ParseHexToBigInt(str string) *big.Int {
	return (&big.Int{}).SetBytes(MustParseHex(str))
}

func ParseDecimalToBigInt(str string) *big.Int {
	i, ok := (&big.Int{}).SetString(str, 10)
	if !ok {
		panic(fmt.Sprintf("Failed to parse decimal integer: %s", str))
	}

	return i
}
