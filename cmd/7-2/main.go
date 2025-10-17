package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/benweissmann/cryptopals/pkg/cbcmac"
	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/padding"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

var cbcHashKey = []byte("YELLOW SUBMARINE")
var cbcHashIv = bytes.Repeat([]byte{0}, 16)

func cbcHash(plaintext string) []byte {
	return cbcmac.CBCMAC([]byte(plaintext), cbcHashIv, cbcHashKey)
}

func main() {
	goodJS := "alert('MZA who was that?');\n"
	validHash := cbcHash(goodJS)

	fmt.Printf("Good JS hash: %x\n", validHash)
	if !bytes.Equal(validHash, convert.MustParseHex("296b8d7cb78a243dda4d0a61d33bbdd1")) {
		panic("Bad hash value")
	}

	badJSPrefix := "alert('Ayo, the Wu is back!');// "

	// To construct a hash collision, we need the final encrypted block to be
	// validHash. We can arrange for this by having the block cipher input be
	// the same as for the valid javascript.
	//
	// So we decrypt validHash under AES to get the desired input, finalBlockInput.
	// Because we're going to be manipulating whole blocks at a time, the plaintext
	// for this final block will always be an all-padding blog, {0x10} x16
	//
	// So our target for the second-to-last ciphertext block is {0x10 x16} ^ decrypt(validHash).
	// If we can arrange for this, then when the verifier computes the final block
	// it will be encrypt({0x10 x16} ^ decrypt(validHash) ^ {0x10 x16}) = encrypt(decrypt(validHash)) = validHash.
	//
	// We will call this target value for the second-to-last ciphertext block targetBlock.
	//
	// In order to produce targetBlock, we need to have the input be decrypt(targetBlock) in the
	// computation of the second-to-last block. That input in turn is:
	//   IV ^ PlaintextSuffix
	// IV is the third-to-last ciphertext block and PlaintextSuffix is the final block of
	// our unpadded input (recall that we expect our malicious payload to be
	// an exact block multiple, so the last block will be all padding and this
	// second-to-last block is the suffix of our malicious code).
	//
	// We can get the IV easily by calculating the hash of the code up to this point:
	// the badJSPrefix above that we can add whatever junk we need to onto the end.
	//
	// So we compute PlaintextSuffix = IV ^ decrypt(targetBlock)
	//
	// Finally, we assemble padded(badJSPrefix) || PlaintextSuffix as our
	// payload.

	blockCipher, err := aes.NewCipher(cbcHashKey)
	if err != nil {
		panic(err)
	}

	finalBlockInput := make([]byte, blockCipher.BlockSize())
	blockCipher.Decrypt(finalBlockInput, validHash)

	paddingBlock := padding.PKCS7Pad([]byte{}, blockCipher.BlockSize())
	targetBlock := xor.Xor(finalBlockInput, paddingBlock)

	targetBlockInput := make([]byte, blockCipher.BlockSize())
	blockCipher.Decrypt(targetBlockInput, targetBlock)

	finalBlockIv := cbcHash(badJSPrefix)

	badJSSuffix := xor.Xor(finalBlockIv, targetBlockInput)

	badJS := padding.PKCS7Pad([]byte(badJSPrefix), blockCipher.BlockSize())
	badJS = append(badJS, badJSSuffix...)

	badJSHash := cbcHash(string(badJS))
	fmt.Printf("Bad JS: %s\n", badJS)
	fmt.Printf("Bad JS hash: %x\n", badJSHash)
	if !bytes.Equal(badJSHash, convert.MustParseHex("296b8d7cb78a243dda4d0a61d33bbdd1")) {
		panic("Bad hash value")
	}
}
