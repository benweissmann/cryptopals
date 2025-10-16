package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/cbcmac"
	"github.com/benweissmann/cryptopals/pkg/padding"
	"github.com/benweissmann/cryptopals/pkg/xor"
)

type RequestV1 struct {
	message string
	iv      []byte
	mac     []byte
}

var key = bytes.Repeat([]byte{0x13}, 16)

func apiServerV1(r *RequestV1) bool {
	// verify MAC
	expectedMac := cbcmac.CBCMAC([]byte(r.message), r.iv, key)

	if !bytes.Equal(expectedMac, r.mac) {
		fmt.Printf("REJECTED request: %s\n", r.message)
		return false
	}

	fmt.Printf("ACCEPTED request: %s\n", r.message)
	return true
}

func webClientGenerateRequestV1(to int, amount int) *RequestV1 {
	// authenticated user's ID
	userId := 123

	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		panic(err)
	}

	msg := fmt.Sprintf("from=%d&to=%d&amount=%d", userId, to, amount)
	mac := cbcmac.CBCMAC([]byte(msg), iv, key)

	return &RequestV1{
		message: msg,
		iv:      iv,
		mac:     mac,
	}
}

func part1() {
	// Valid request
	// Transfer from attacker (123) to target (456) $1M
	origReq := webClientGenerateRequestV1(456, 1000000)
	res := apiServerV1(origReq)
	if !res {
		panic("Fail")
	}

	// Invalid request
	// Transfer from target to attacker
	forgedMsg := "from=456&to=123&amount=1000000"
	badForgedReq := &RequestV1{
		message: forgedMsg,
		iv:      origReq.iv,
		mac:     origReq.mac,
	}
	res = apiServerV1(badForgedReq)
	if res {
		panic("Fail")
	}

	// Compute mailicious IV
	//
	// The block cipher input for the first block is:
	//   m0 ^ iv   (first block of the message, xor the IV)
	//
	// We want to feed the server a malicious IV, iv', that will end up with
	// the same block cipher input for the first block with our forged message, m',
	// as the real message.
	//
	// So we want to solve for iv' (the malicious IV) in:
	//    m'0 ^ iv' = m0 ^ iv (forged message first block xor malicious IV gives same input as the real message)
	//
	// iv' = m0 ^ iv & m'0
	forgedFirstBlock := []byte(forgedMsg[0:16])
	realFirstBlock := []byte(origReq.message[0:16])
	maliciousIV := xor.Xor(xor.Xor(realFirstBlock, origReq.iv), forgedFirstBlock)

	goodForgedReq := &RequestV1{
		message: forgedMsg,
		iv:      maliciousIV,
		mac:     origReq.mac,
	}
	res = apiServerV1(goodForgedReq)
	if !res {
		panic("Fail")
	}
}

var fixedIV = bytes.Repeat([]byte{0}, 16)

type RequestV2 struct {
	message string
	mac     []byte
}

func apiServerV2(r *RequestV2) bool {
	// verify MAC
	expectedMac := cbcmac.CBCMAC([]byte(r.message), fixedIV, key)

	if !bytes.Equal(expectedMac, r.mac) {
		fmt.Printf("REJECTED request: %s\n", r.message)
		return false
	}

	fmt.Printf("ACCEPTED request: %s\n", r.message)
	return true
}

type Tx struct {
	to     int
	amount int
}

func webClientGenerateRequestV2(userId int, txs []Tx) *RequestV2 {
	txList := make([]string, len(txs))
	for i, tx := range txs {
		txList[i] = fmt.Sprintf("%d:%d", tx.to, tx.amount)
	}

	msg := fmt.Sprintf("from=%d&tx_list=%s", userId, strings.Join(txList, ";"))
	mac := cbcmac.CBCMAC([]byte(msg), fixedIV, key)

	return &RequestV2{
		message: msg,
		mac:     mac,
	}
}

func part2() {
	// Valid request
	// Victim intentionally transfers from thier account (123) to associate (456)
	origReq := webClientGenerateRequestV2(123, []Tx{
		{
			to:     456,
			amount: 100,
		},
	})
	res := apiServerV2(origReq)
	if !res {
		panic("Fail")
	}

	// Invalid request
	// Add a second transaction
	forgedMsg := origReq.message + ";999:1000000"
	badForgedReq := &RequestV2{
		message: forgedMsg,
		mac:     origReq.mac,
	}
	res = apiServerV2(badForgedReq)
	if res {
		panic("Fail")
	}

	// Forge the signature

	// First, the attacker uses their account to generate a valid message with
	// the transaction we want
	attackerMsg := webClientGenerateRequestV2(999, []Tx{
		{
			to:     999,
			amount: 0,
		},
		{
			to:     999,
			amount: 100,
		},
	})
	fmt.Printf("Good msg     : %x\n", padding.PKCS7Pad([]byte(origReq.message), 16))
	fmt.Printf("Attacker msg : %x\n", padding.PKCS7Pad([]byte(attackerMsg.message), 16))

	// now, we generate a "transition block" -- this is a variant of the first block
	// of the attacker message that can be added to the original message to sync the
	// CBC state with the attacker's message.
	//
	// When we add this block to the end of the original message, CBC will encrypt
	// this block with the original MAC as the IV. We want to have this match the
	// encryption done on the first block of the attacker's message.
	//
	//   origMac ^ transitionBlock = iv ^ attackerMsg[0]
	//   transitionBlock = iv ^ attackerMsg[0] ^ origMac
	transitionBlock := xor.Xor(
		xor.Xor(fixedIV, []byte(attackerMsg.message)[0:16]),
		origReq.mac,
	)
	fmt.Printf("Transition   : %x\n", transitionBlock)

	// Then, we can append the rest of the attacker's message as-is
	newForgedMsg := bytes.Join(
		[][]byte{
			padding.PKCS7Pad([]byte(origReq.message), 16),
			transitionBlock,
			[]byte(attackerMsg.message)[16:],
		},
		[]byte{},
	)
	fmt.Printf("newForgedMsg : %x\n", newForgedMsg)

	goodForgedReq := &RequestV2{
		message: string(newForgedMsg),
		mac:     attackerMsg.mac,
	}
	res = apiServerV2(goodForgedReq)
	if !res {
		panic("Fail")
	}
}

func main() {
	part2()
}
