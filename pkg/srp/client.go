package srp

import (
	"crypto/rand"
	"math/big"
)

func ComputeSRPClientToken(p string, salt []byte, bPub *big.Int) (clientToken []byte, aPub *big.Int) {
	aPriv, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}

	aPub = big.NewInt(0)
	aPub.Exp(big.NewInt(g), aPriv, n)

	u := computeU(aPub, bPub)
	x := computeX(p, salt)

	var aux big.Int
	aux.Mul(u, x)
	aux.Add(aPriv, &aux)

	var bkgx big.Int
	bkgx.Exp(big.NewInt(g), x, n)
	bkgx.Mul(big.NewInt(k), &bkgx)
	bkgx.Sub(bPub, &bkgx)
	bkgx.Mod(&bkgx, n)

	var s big.Int
	s.Exp(&bkgx, &aux, n)

	k := ComputeK(&s)

	return ComputeFinalHmac(k, salt), aPub
}
