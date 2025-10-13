package rsa

import (
	"crypto/rand"
	"math/big"
)

type Keypair struct {
	n *big.Int
	e *big.Int
	d *big.Int
}

type PublicKey struct {
	e *big.Int
	n *big.Int
}

const KEY_SIZE = 2048

func NewKeypair() *Keypair {
	for {
		p, err := rand.Prime(rand.Reader, KEY_SIZE/2)
		if err != nil {
			panic(err)
		}

		q, err := rand.Prime(rand.Reader, KEY_SIZE/2)
		if err != nil {
			panic(err)
		}

		n := (&big.Int{}).Mul(p, q)

		et := (&big.Int{}).Mul(
			(&big.Int{}).Sub(p, big.NewInt(1)),
			(&big.Int{}).Sub(q, big.NewInt(1)),
		)

		e := big.NewInt(3)

		d := (&big.Int{}).ModInverse(e, et)

		if d == nil {
			continue
		}

		return &Keypair{
			n: n,
			e: e,
			d: d,
		}
	}
}

func (k *Keypair) PublicKey() *PublicKey {
	return &PublicKey{
		e: k.e,
		n: k.n,
	}
}

func (k *Keypair) Decrypt(ciphertext *big.Int) *big.Int {
	return (&big.Int{}).Exp(ciphertext, k.d, k.n)
}

func (k *Keypair) DecryptBytes(ciphertext []byte) string {
	ciphertextInt := (&big.Int{}).SetBytes(ciphertext)
	cleartextInt := k.Decrypt(ciphertextInt)

	return string(cleartextInt.Bytes())
}

func (p *PublicKey) Encrypt(cleartext *big.Int) *big.Int {
	return (&big.Int{}).Exp(cleartext, p.e, p.n)
}

func (p *PublicKey) EncryptString(cleartext string) []byte {
	return p.EncryptStringToInt(cleartext).Bytes()
}

func (p *PublicKey) EncryptStringToInt(cleartext string) *big.Int {
	cleartextInt := (&big.Int{}).SetBytes([]byte(cleartext))
	return p.Encrypt(cleartextInt)
}

func (p *PublicKey) N() *big.Int {
	return p.n
}
