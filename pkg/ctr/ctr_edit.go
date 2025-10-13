package ctr

import "encoding/binary"

func (x *ctr) Edit(ciphertext []byte, offset int, newCleartext []byte) {
	cryptIn := make([]byte, x.blockSize)
	_, err := binary.Encode(cryptIn[0:x.blockSize/2], binary.LittleEndian, x.nonce)
	if err != nil {
		panic(err.Error())
	}

	currentBlockCryptOut := make([]byte, x.blockSize)
	currentBlockIndex := -1

	for ctIndex, newCleartextByte := range newCleartext {
		i := offset + ctIndex
		blockIndex := i / x.blockSize

		if blockIndex != currentBlockIndex {
			_, err := binary.Encode(cryptIn[x.blockSize/2:x.blockSize], binary.LittleEndian, int64(blockIndex))
			if err != nil {
				panic(err.Error())
			}

			x.b.Encrypt(currentBlockCryptOut, cryptIn)

			currentBlockIndex = blockIndex
		}

		ciphertext[i] = newCleartextByte ^ currentBlockCryptOut[i%x.blockSize]
	}
}
