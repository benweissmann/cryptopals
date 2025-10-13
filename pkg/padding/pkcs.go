package padding

func PKCS7Pad(input []byte, blockSize int) []byte {
	inputLen := len(input)
	outputLen := ((inputLen / blockSize) + 1) * blockSize
	padding := byte(outputLen - inputLen)

	output := make([]byte, outputLen)
	copy(output, input)

	for i := inputLen; i < outputLen; i++ {
		output[i] = padding
	}

	return output
}

func PKCS7Unpad(input []byte) []byte {
	padLength := input[len(input)-1]
	return input[:len(input)-int(padLength)]
}

func VerifyPKCSPadding(input []byte) (unpadded []byte, ok bool) {
	padLength := input[len(input)-1]
	if int(padLength) > len(input) {
		return nil, false
	}
	if padLength == 0 {
		return nil, false
	}

	for i := len(input) - int(padLength); i < len(input); i++ {
		if input[i] != padLength {
			return nil, false
		}
	}

	return input[:len(input)-int(padLength)], true
}
