package bleichenbacheroracle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/rsa"
)

type OracleFn = func(ciphertext *big.Int) bool

func Oracle(keypair *rsa.Keypair, ciphertext *big.Int) bool {
	decryptedRaw := keypair.Decrypt(ciphertext).Bytes()
	decrypted := make([]byte, keypair.KeySize()/8)
	copy(decrypted[keypair.KeySize()/8-len(decryptedRaw):], decryptedRaw)

	if decrypted[0] == 0x00 && decrypted[1] == 0x02 {
		return true
	}

	return false
}

func MakeOracle(keypair *rsa.Keypair) OracleFn {
	return func(ciphertext *big.Int) bool {
		return Oracle(keypair, ciphertext)
	}
}

func PKCS15Pad(msg []byte, keySize int) []byte {
	byteLength := keySize / 8

	padLength := byteLength - 3 - len(msg)
	if padLength < 8 {
		panic("Padding must be at least 8 bytes")
	}

	padding := make([]byte, padLength)
	rand.Read(padding)
	for i := range padding {
		for padding[i] == 0 {
			rand.Read(padding[i : i+1])
		}
	}

	res := bytes.Join([][]byte{
		{0x00, 0x02},
		padding,
		{0x00},
		msg,
	}, []byte{})

	if len(res) != byteLength {
		panic(fmt.Sprintf("Incorrect final byte length: %d", len(res)))
	}

	return res
}

func OracleAttack(oracle OracleFn, pubKey *rsa.PublicKey, ciphertext *big.Int) *big.Int {
	testS := func(s *big.Int) bool {
		se := (&big.Int{}).Exp(s, pubKey.E(), pubKey.N())

		testCiphertext := (&big.Int{}).Mul(ciphertext, se)
		testCiphertext.Mod(testCiphertext, pubKey.N())

		return oracle(testCiphertext)
	}

	k := pubKey.KeySize() / 8
	B := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(int64(8*(k-2))), nil)
	twoB := (&big.Int{}).Mul(B, two)
	threeB := (&big.Int{}).Mul(B, three)

	M := &RangeSet{}
	M.Add(NewRange(
		twoB,
		(&big.Int{}).Sub(threeB, one),
	))
	fmt.Printf("Starting M: %s\n", M)

	i := 1
	var s *big.Int

	for {
		fmt.Printf("\n\n\nITERATION %d\n\n", i)
		// step 2: searching for PKCS conforming messages
		if i == 1 {
			// 2a
			fmt.Printf("Step 2a: Initialization\n")
			s = (&big.Int{}).Div(pubKey.N(), threeB)
			fmt.Printf("  Starting S: %d\n", s)
			for {
				s.Add(s, one)

				if testS(s) {
					fmt.Printf("  Found suitable S: %d\n", s)
					break
				}
			}
		} else if M.Size() > 1 {
			// 2b
			fmt.Printf("Step 2b: Multiple ranges\n")
			fmt.Printf("  Starting S: %d\n", s)

			for {
				s.Add(s, one)

				if testS(s) {
					fmt.Printf("  Found suitable S: %d\n", s)
					break
				}
			}
		} else {
			// 2c
			a := M.Ranges[0].Min
			b := M.Ranges[0].Max

			fmt.Printf("Step 2c: Searching within single range\n")
			fmt.Printf("  Narrowing within range: %d - %d\n", a, b)

			bs := (&big.Int{}).Mul(b, s)
			bsMinus2B := (&big.Int{}).Sub(bs, twoB)
			quo := floorDiv(bsMinus2B, pubKey.N())
			r := (&big.Int{}).Mul(two, quo)

			for {
				if r.Int64()%10000 == 0 {
					fmt.Printf("    Searching with r = %s\n", r)
				}
				foundS := false

				rn := (&big.Int{}).Mul(r, pubKey.N())

				sMax := ceilDiv((&big.Int{}).Add(threeB, rn), a)
				s = floorDiv((&big.Int{}).Add(twoB, rn), b)

				for lt(s, sMax) {
					if testS(s) {
						fmt.Printf("Found suitable s: %s\n", s)
						foundS = true
						break
					}
					s.Add(s, one)
				}

				if foundS {
					break
				} else {
					r.Add(r, one)
				}
			}
		}

		fmt.Printf("S: %d\n", s)

		// step 3: Narrowing the set of solutions
		newM := &RangeSet{}
		fmt.Printf("Narrowing ranges\n")
		for _, oldRange := range M.Ranges {
			fmt.Printf("  Narrowing old range: %s\n", oldRange)
			a := oldRange.Min
			b := oldRange.Max

			bs := (&big.Int{}).Mul(b, s)
			rMaxNum := (&big.Int{}).Sub(bs, twoB)
			rMax := floorDiv(rMaxNum, pubKey.N())

			as := (&big.Int{}).Mul(a, s)
			rMinNum := (&big.Int{}).Sub(as, threeB)
			rMinNum.Add(rMinNum, one)

			r := ceilDiv(rMinNum, pubKey.N())
			for lte(r, rMax) {
				fmt.Printf("    r = %d\n", r)
				rn := (&big.Int{}).Mul(r, pubKey.N())

				newMinNum := (&big.Int{}).Add(twoB, rn)
				newMin := ceilDiv(newMinNum, s)
				fmt.Printf("    newMin = %d\n", newMin)

				newMaxNum := (&big.Int{}).Add(threeB, rn)
				newMaxNum.Sub(newMaxNum, one)
				newMax := floorDiv(newMaxNum, s)
				fmt.Printf("    newMax = %d\n", newMax)

				newM.Add(NewRange(
					max(a, newMin),
					min(b, newMax),
				))

				r.Add(r, one)
			}
		}

		M = newM
		fmt.Printf("M: %s\n", M)

		// step 4: computing the solution
		solution := M.SingleValue()
		if solution != nil {
			return solution
		}

		i++
	}
}
