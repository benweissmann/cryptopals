package ctr

import (
	"crypto/rand"
	"encoding/binary"
)

func RandomIV() uint64 {
	data := make([]byte, 8)
	_, err := rand.Read(data)
	if err != nil {
		panic(err.Error())
	}

	return binary.LittleEndian.Uint64(data)
}
