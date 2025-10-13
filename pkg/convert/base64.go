package convert

import "encoding/base64"

func MustParseBase64(base64Str string) []byte {
	b64Bytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		panic(err.Error())
	}

	return b64Bytes
}
