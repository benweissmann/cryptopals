package main

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/dsa"
	"github.com/benweissmann/cryptopals/pkg/sha1"
)

type SignedMessage struct {
	msg     []byte
	sig     *dsa.Signature
	msgHash []byte
}

func crackPrivateKey(pubKey *dsa.PublicKey, messages []SignedMessage) *dsa.Keypair {
	q := pubKey.Params.Q

	for i1, m1 := range messages {
		for _, m2 := range messages[i1:] {
			// Attempt to recover k from m1 / m2 if their k was reused
			msgDiff := (&big.Int{}).Sub(sha1.HashToBigInt(m1.msg), sha1.HashToBigInt((m2.msg)))
			msgDiff.Mod(msgDiff, q)

			sDiff := (&big.Int{}).Sub(m1.sig.S, m2.sig.S)
			sDiff.Mod(sDiff, q)

			if sDiff.Cmp(big.NewInt(0)) == 0 {
				continue
			}

			reusedK := (&big.Int{}).Mul(msgDiff, (&big.Int{}).ModInverse(sDiff, q))
			reusedK.Mod(reusedK, q)

			if reusedK.Cmp(big.NewInt(0)) == 0 {
				continue
			}

			recovered := dsa.RecoverPrivateKeyFromK(reusedK, m1.msg, m1.sig, pubKey)

			// Check if the recovered private key is correct
			testSig := recovered.SignWithGivenK(m1.msg, reusedK)
			if testSig.R.Cmp(m1.sig.R) == 0 && testSig.S.Cmp(m1.sig.S) == 0 {
				return recovered
			}
		}
	}

	return nil
}

func main() {
	messages := []SignedMessage{
		{
			msg: []byte("Listen for me, you better listen for me now. "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("1267396447369736888040262262183731677867615804316"),
				R: convert.ParseDecimalToBigInt("1105520928110492191417703162650245113664610474875"),
			},
			msgHash: convert.MustParseHex("a4db3de27e2db3e5ef085ced2bced91b82e0df19"),
		},
		{
			msg: []byte("Listen for me, you better listen for me now. "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("29097472083055673620219739525237952924429516683"),
				R: convert.ParseDecimalToBigInt("51241962016175933742870323080382366896234169532"),
			},
			msgHash: convert.MustParseHex("a4db3de27e2db3e5ef085ced2bced91b82e0df19"),
		},
		{
			msg: []byte("When me rockin' the microphone me rock on steady, "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("277954141006005142760672187124679727147013405915"),
				R: convert.ParseDecimalToBigInt("228998983350752111397582948403934722619745721541"),
			},
			msgHash: convert.MustParseHex("21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4"),
		},
		{
			msg: []byte("Yes a Daddy me Snow me are de article dan. "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("1013310051748123261520038320957902085950122277350"),
				R: convert.ParseDecimalToBigInt("1099349585689717635654222811555852075108857446485"),
			},
			msgHash: convert.MustParseHex("1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5"),
		},
		{
			msg: []byte("But in a in an' a out de dance em "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("203941148183364719753516612269608665183595279549"),
				R: convert.ParseDecimalToBigInt("425320991325990345751346113277224109611205133736"),
			},
			msgHash: convert.MustParseHex("6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff"),
		},
		{
			msg: []byte("Aye say where you come from a, "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("502033987625712840101435170279955665681605114553"),
				R: convert.ParseDecimalToBigInt("486260321619055468276539425880393574698069264007"),
			},
			msgHash: convert.MustParseHex("5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9"),
		},
		{
			msg: []byte("People em say ya come from Jamaica, "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("1133410958677785175751131958546453870649059955513"),
				R: convert.ParseDecimalToBigInt("537050122560927032962561247064393639163940220795"),
			},
			msgHash: convert.MustParseHex("7d9abd18bbecdaa93650ecc4da1b9fcae911412"),
		},
		{
			msg: []byte("But me born an' raised in the ghetto that I want yas to know, "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("559339368782867010304266546527989050544914568162"),
				R: convert.ParseDecimalToBigInt("826843595826780327326695197394862356805575316699"),
			},
			msgHash: convert.MustParseHex("88b9e184393408b133efef59fcef85576d69e249"),
		},
		{
			msg: []byte("Pure black people mon is all I mon know. "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("1021643638653719618255840562522049391608552714967"),
				R: convert.ParseDecimalToBigInt("1105520928110492191417703162650245113664610474875"),
			},
			msgHash: convert.MustParseHex("d22804c4899b522b23eda34d2137cd8cc22b9ce8"),
		},
		{
			msg: []byte("Yeah me shoes a an tear up an' now me toes is a show a "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("506591325247687166499867321330657300306462367256"),
				R: convert.ParseDecimalToBigInt("51241962016175933742870323080382366896234169532"),
			},
			msgHash: convert.MustParseHex("bc7ec371d951977cba10381da08fe934dea80314"),
		},
		{
			msg: []byte("Where me a born in are de one Toronto, so "),
			sig: &dsa.Signature{
				S: convert.ParseDecimalToBigInt("458429062067186207052865988429747640462282138703"),
				R: convert.ParseDecimalToBigInt("228998983350752111397582948403934722619745721541"),
			},
			msgHash: convert.MustParseHex("d6340bfcda59b6b75b59ca634813d572de800e8f"),
		},
	}

	params := dsa.DefaultParams()

	pubKey := &dsa.PublicKey{
		Y: convert.ParseHexToBigInt(
			"2d026f4bf30195ede3a088da85e398ef869611d0f68f07" +
				"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" +
				"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" +
				"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" +
				"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" +
				"2971c3de5084cce04a2e147821"),
		Params: params,
	}

	// confirm that all message hashes match and all signatures are valid
	for _, m := range messages {
		sha := sha1.New()
		sha.Write(m.msg)
		sum := sha.Sum([]byte{})

		if !bytes.Equal(sum, m.msgHash) {
			panic(fmt.Sprintf("Mismatched hash for message %s: got %x expected %x", m.msg, sum, m.msgHash))
		}

		sigOk, sigErr := pubKey.Verify(m.msg, m.sig)
		if !sigOk {
			panic(sigErr)
		}
	}

	fmt.Println("All inputs passed validation")

	privKey := crackPrivateKey(pubKey, messages)

	if privKey == nil {
		panic("Failed to crack private key")
	}

	privKeyHex := fmt.Sprintf("%x", privKey.X)
	fmt.Printf("Found key: %x\n", privKeyHex)

	kSum := sha1.New()
	kSum.Write([]byte(privKeyHex))

	fmt.Printf("Digest: %x\n", kSum.Sum([]byte{}))
}
