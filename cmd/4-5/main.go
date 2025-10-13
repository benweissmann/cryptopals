package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/sha1"
)

func forgeSignature(originalSession []byte, additionalSession []byte, originalSignature []byte, testSignature func(session []byte, signature []byte) bool) (session []byte, signature []byte) {
	// Need to guess original key length
	for i := uint64(1); i < 100; i++ {
		originalHashLength := uint64(len(originalSession)) + i
		padding := sha1.Padding(originalHashLength)

		newSession := bytes.Join([][]byte{originalSession, padding, additionalSession}, []byte{})

		newHash := sha1.Resume(originalSignature, originalHashLength+uint64(len(padding)))
		newHash.Write(additionalSession)
		newSig := newHash.Sum([]byte{})

		if testSignature(newSession, newSig) {
			return newSession, newSig
		}
	}

	panic("Could not forge signature")
}

func main() {
	key := []byte(convert.RandomPassword())

	generateSessionData := func() (session []byte, signature []byte) {
		sessionData := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

		hash := sha1.New()
		hash.Write(key)
		hash.Write(sessionData)

		sig := []byte{}
		return sessionData, hash.Sum(sig)
	}

	isAdmin := func(session []byte, signature []byte) (bool, error) {
		hash := sha1.New()
		hash.Write(key)
		hash.Write(session)

		correctSig := []byte{}
		correctSig = hash.Sum(correctSig)

		if !bytes.Equal(correctSig, signature) {
			return false, fmt.Errorf("Bad signature")
		}

		return strings.Contains(string(session), ";admin=true;"), nil
	}

	session, sig := generateSessionData()

	initialIsAdmin, err := isAdmin(session, sig)
	if err != nil {
		panic(err.Error())
	}
	if initialIsAdmin {
		panic("initial session was admin")
	}

	// make sure bad signature is rejected
	tamperedIsAdmin, err := isAdmin([]byte(string(session)+";admin=true;"), sig)
	if err == nil {
		panic("tampered session passed validation")
	}
	if tamperedIsAdmin {
		panic("tampered session was admin")
	}

	forgedSession, forgedSignature := forgeSignature(session, []byte(";admin=true;"), sig, func(testSession []byte, testSig []byte) bool {
		_, err := isAdmin(testSession, testSig)
		return err == nil
	})

	forgedIsAdmin, err := isAdmin(forgedSession, forgedSignature)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Forged is admin: %t\n", forgedIsAdmin)
}
