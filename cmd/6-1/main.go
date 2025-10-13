package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/rsa"
)

type Server struct {
	keypair rsa.Keypair
	cache   map[string]bool
}

func NewServer() *Server {
	return &Server{
		keypair: *rsa.NewKeypair(),
		cache:   make(map[string]bool),
	}
}

func (s *Server) Decrypt(ciphertext *big.Int) *big.Int {
	hashBytes := sha256.Sum256(ciphertext.Bytes())
	hash := string(hashBytes[:])

	if s.cache[hash] {
		return big.NewInt(-1)
	}

	s.cache[hash] = true

	return s.keypair.Decrypt(ciphertext)
}

func (s *Server) DecryptToString(ciphertext *big.Int) string {
	p := s.Decrypt(ciphertext)

	if p.Cmp(big.NewInt(-1)) == 0 {
		return "Rejected"
	}

	return string(p.Bytes())
}

func (s *Server) Encrypt(plaintext string) *big.Int {
	return s.keypair.PublicKey().EncryptStringToInt(plaintext)
}

func (s *Server) PublicParams() (n *big.Int, e *big.Int) {
	return s.keypair.PublicKey().N(), big.NewInt(3)
}

func main() {
	server := NewServer()

	c := server.Encrypt("My SSN")
	fmt.Println("First decryption: " + server.DecryptToString(c))
	fmt.Println("Second decryption: " + server.DecryptToString(c))
	fmt.Println("Third decryption: " + server.DecryptToString(c))

	n, e := server.PublicParams()
	s, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}

	cp := (&big.Int{}).Exp(s, e, n)
	cp.Mul(cp, c)
	cp.Mod(cp, n)

	pp := server.Decrypt(cp)

	p := (&big.Int{}).Mul(pp, (&big.Int{}).ModInverse(s, n))
	p.Mod(p, n)

	fmt.Println("Hacked: " + string(p.Bytes()))
}
