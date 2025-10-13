package srplite

import (
	"crypto/rand"
	"math/big"
)

type SRPClientSession struct {
	aPriv *big.Int
	aPub  *big.Int
}

func NewClientSession() *SRPClientSession {
	aPriv, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}

	aPub := (&big.Int{}).Exp(big.NewInt(g), aPriv, n)

	return &SRPClientSession{
		aPriv: aPriv,
		aPub:  aPub,
	}
}

func (sess *SRPClientSession) PubKey() *big.Int {
	return sess.aPub
}

func (sess *SRPClientSession) ComputeSRPClientToken(p string, salt []byte, bPub *big.Int, u *big.Int) (clientToken []byte) {
	x := computeX(p, salt)

	var aux big.Int
	aux.Mul(u, x)
	aux.Add(sess.aPriv, &aux)

	s := (&big.Int{}).Exp(bPub, &aux, n)

	k := ComputeK(s)

	return ComputeFinalHmac(k, salt)
}
