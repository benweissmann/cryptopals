package convert

import (
	"encoding/json"
	"fmt"
)

func EscapedPrintBytes(val []byte) {
	jsonOut, err := json.Marshal(string(val))
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(string(jsonOut[1 : len(jsonOut)-1]))
}
