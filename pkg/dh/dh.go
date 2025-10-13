package dh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/sha1"
)

var DefaultP = big.NewInt(0)
var DefaultG = big.NewInt(2)

func init() {
	DefaultP.SetString(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
		16,
	)
}

type DHKeypair struct {
	p *big.Int
	g *big.Int

	pubKey  *big.Int
	privKey *big.Int
}

func GenerateKeypairWithParams(p *big.Int, g *big.Int) (*DHKeypair, error) {
	privKey, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, err
	}

	var pubKey big.Int
	pubKey.Exp(g, privKey, p)

	return &DHKeypair{
		p:       p,
		g:       g,
		pubKey:  &pubKey,
		privKey: privKey,
	}, nil
}

func GenerateKeypair() (*DHKeypair, error) {
	return GenerateKeypairWithParams(DefaultP, DefaultG)
}

func (keypair *DHKeypair) Params() (*big.Int, *big.Int) {
	return keypair.p, keypair.g
}

func (keypair *DHKeypair) PubKey() *big.Int {
	return keypair.pubKey
}

func (keypair *DHKeypair) SessionKey(otherPublicKey *big.Int) *big.Int {
	var session big.Int
	session.Exp(otherPublicKey, keypair.privKey, keypair.p)

	return &session
}

func (keypair *DHKeypair) AESSession(otherPublicKey *big.Int) cipher.Block {
	return AESSessionFromSessionKey(keypair.SessionKey(otherPublicKey))
}

func AESSessionFromSessionKey(sessionKey *big.Int) cipher.Block {
	digest := sha1.New()
	_, err := digest.Write(sessionKey.Bytes())
	if err != nil {
		panic(err.Error())
	}

	digestBytes := digest.Sum([]byte{})
	block, err := aes.NewCipher(digestBytes[:16])
	if err != nil {
		panic(err.Error())
	}

	return block
}
