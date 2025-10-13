package plaintextscore

func HasHighAscii(input []byte) bool {
	for _, b := range input {
		if b > 128 {
			return true
		}
	}

	return false
}
