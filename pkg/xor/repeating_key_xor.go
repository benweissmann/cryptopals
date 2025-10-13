package xor

func RepeatingKeyXor(plaintext string, key string) []byte {
	plaintextBytes := []byte(plaintext)
	keyBytes := []byte(key)

	out := make([]byte, len(plaintextBytes))

	for i, plainByte := range plaintextBytes {
		keyByte := keyBytes[i%len(keyBytes)]
		out[i] = plainByte ^ keyByte
	}

	return out
}
