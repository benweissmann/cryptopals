package convert

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func Hex2base64(hexStr string) (string, error) {
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("Unable to decode hex string: %w", err)
	}

	return base64.RawStdEncoding.EncodeToString(hexBytes), nil
}
