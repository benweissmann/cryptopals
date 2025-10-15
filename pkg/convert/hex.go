package convert

import "encoding/hex"

func MustParseHex(hexStr string) []byte {
	paddedHex := hexStr
	if len(hexStr)%2 == 1 {
		paddedHex = "0" + hexStr
	}

	hexBytes, err := hex.DecodeString(paddedHex)
	if err != nil {
		panic(err.Error())
	}

	return hexBytes
}
