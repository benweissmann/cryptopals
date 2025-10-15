package dsa

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/benweissmann/cryptopals/pkg/convert"
	"github.com/benweissmann/cryptopals/pkg/sha1"
)

type Params struct {
	P                    *big.Int
	Q                    *big.Int
	G                    *big.Int
	SkipZeroVerification bool
}

type Keypair struct {
	Params *Params
	X      *big.Int
	Y      *big.Int
}

type PublicKey struct {
	Params *Params
	Y      *big.Int
}

type Signature struct {
	R *big.Int
	S *big.Int
}

func DefaultParams() *Params {
	p := (&big.Int{}).SetBytes(convert.MustParseHex("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"))

	q := (&big.Int{}).SetBytes((convert.MustParseHex("f4f47f05794b256174bba6e9b396a7707e563c5b")))

	g := (&big.Int{}).SetBytes(convert.MustParseHex("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"))

	return &Params{
		P: p,
		Q: q,
		G: g,
	}
}

func GenerateKey(max *big.Int) *big.Int {
	k, err := rand.Int(rand.Reader, (&big.Int{}).Sub(max, big.NewInt(1)))
	if err != nil {
		panic(err)
	}

	return k.Add(k, big.NewInt(1))
}

func NewKeypair(params *Params) *Keypair {
	x := GenerateKey(params.Q)

	y := (&big.Int{}).Exp(params.G, x, params.P)

	return &Keypair{
		Params: params,
		X:      x,
		Y:      y,
	}
}

func (k *Keypair) PublicKey() *PublicKey {
	return &PublicKey{
		Params: k.Params,
		Y:      k.Y,
	}
}

func (keypair *Keypair) GenerateK() *big.Int {
	return GenerateKey(keypair.Params.Q)
}

func (keypair *Keypair) Sign(m []byte) *Signature {
	return keypair.SignWithGivenK(m, keypair.GenerateK())
}

func (keypair *Keypair) SignWithGivenK(m []byte, k *big.Int) *Signature {
	p := keypair.Params.P
	q := keypair.Params.Q
	g := keypair.Params.G

	r := (&big.Int{}).Exp(g, k, p)
	r.Mod(r, q)

	if !keypair.Params.SkipZeroVerification && r.Cmp(big.NewInt(0)) == 0 {
		// edge case: r == 0; try again
		return keypair.Sign(m)
	}

	h := sha1.HashToBigInt(m)

	xr := (&big.Int{}).Mul(keypair.X, r)
	xr.Mod(xr, q)

	hSum := (&big.Int{}).Add(h, xr)
	hSum.Mod(hSum, q)

	s := (&big.Int{}).Mul(hSum, (&big.Int{}).ModInverse(k, q))
	s.Mod(s, q)

	if !keypair.Params.SkipZeroVerification && s.Cmp(big.NewInt(0)) == 0 {
		// edge case: s == 0; try again
		return keypair.Sign(m)
	}

	return &Signature{
		S: s,
		R: r,
	}
}

func (pubkey *PublicKey) Verify(m []byte, sig *Signature) (bool, error) {
	p := pubkey.Params.P
	q := pubkey.Params.Q
	g := pubkey.Params.G

	// Verify signature range
	if !pubkey.Params.SkipZeroVerification && sig.R.Cmp(big.NewInt(0)) != 1 {
		return false, fmt.Errorf("r must be >0")
	}

	if !pubkey.Params.SkipZeroVerification && sig.R.Cmp(q) != -1 {
		return false, fmt.Errorf("r must be <q")
	}

	if !pubkey.Params.SkipZeroVerification && sig.S.Cmp(big.NewInt(0)) != 1 {
		return false, fmt.Errorf("s must be >0")
	}

	if !pubkey.Params.SkipZeroVerification && sig.S.Cmp(q) != -1 {
		return false, fmt.Errorf("s must be <q")
	}

	w := (&big.Int{}).ModInverse(sig.S, q)

	u1 := (&big.Int{}).Mul(sha1.HashToBigInt(m), w)
	u1.Mod(u1, q)

	u2 := (&big.Int{}).Mul(sig.R, w)
	u2.Mod(u2, q)

	gExp := (&big.Int{}).Exp(g, u1, p)
	yExp := (&big.Int{}).Exp(pubkey.Y, u2, p)

	v := (&big.Int{}).Mul(gExp, yExp)
	v.Mod(v, p)
	v.Mod(v, q)

	if v.Cmp(sig.R) == 0 {
		return true, nil
	}

	return false, fmt.Errorf("Mismatched signature verifier: Got %x but expected %x", v, sig.R)
}
