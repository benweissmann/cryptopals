package convert

import "encoding/hex"

func MustParseHex(hexStr string) []byte {
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err.Error())
	}

	return hexBytes
}
