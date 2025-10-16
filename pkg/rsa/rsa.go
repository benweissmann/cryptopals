package rsa

import (
	"crypto/rand"
	"math/big"
)

type Keypair struct {
	n *big.Int
	e *big.Int
	d *big.Int

	keySize int
}

type PublicKey struct {
	e *big.Int
	n *big.Int

	keySize int
}

const KEY_SIZE = 2048

var DefaultE = big.NewInt(3)

func NewKeypair() *Keypair {
	return NewKeypairWithParams(KEY_SIZE, DefaultE)
}

func NewKeypairWithParams(keySize int, e *big.Int) *Keypair {
	for {
		p, err := rand.Prime(rand.Reader, keySize/2)
		if err != nil {
			panic(err)
		}

		q, err := rand.Prime(rand.Reader, keySize/2)
		if err != nil {
			panic(err)
		}

		n := (&big.Int{}).Mul(p, q)

		et := (&big.Int{}).Mul(
			(&big.Int{}).Sub(p, big.NewInt(1)),
			(&big.Int{}).Sub(q, big.NewInt(1)),
		)

		e := (&big.Int{}).Set(e)

		d := (&big.Int{}).ModInverse(e, et)

		if d == nil {
			continue
		}

		return &Keypair{
			n: n,
			e: e,
			d: d,

			keySize: keySize,
		}
	}
}

func (k *Keypair) PublicKey() *PublicKey {
	return &PublicKey{
		e: k.e,
		n: k.n,

		keySize: k.keySize,
	}
}

func (k *Keypair) KeySize() int {
	return k.keySize
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

func (p *PublicKey) E() *big.Int {
	return (&big.Int{}).Set(p.e)
}

func (p *PublicKey) N() *big.Int {
	return (&big.Int{}).Set(p.n)
}

func (k *PublicKey) KeySize() int {
	return k.keySize
}
