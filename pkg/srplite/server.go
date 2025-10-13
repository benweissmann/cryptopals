package srplite

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"math/big"
)

type SRPServer struct {
	i    string
	v    *big.Int
	salt []byte
}

func randomSalt() []byte {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err.Error())
	}

	return salt
}

func NewSRPServer(i string, p string) *SRPServer {
	salt := randomSalt()

	x := computeX(p, salt)

	var v big.Int
	v.Exp(big.NewInt(g), x, n)

	return &SRPServer{
		i:    i,
		v:    &v,
		salt: salt,
	}
}

type SRPServerSession struct {
	server *SRPServer
	bPriv  *big.Int
	bPub   *big.Int
	aPub   *big.Int
	u      *big.Int
}

func (server *SRPServer) NewSession(i string, aPub *big.Int) (serverSession *SRPServerSession) {
	if i != server.i {
		panic(fmt.Errorf("Mismatched i: client %s ; server %s", i, server.i))
	}

	bPriv, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}

	bPub := (&big.Int{}).Exp(big.NewInt(g), bPriv, n)

	u, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		panic(err)
	}

	return &SRPServerSession{
		server: server,
		bPriv:  bPriv,
		bPub:   bPub,
		aPub:   aPub,
		u:      u,
	}
}

func (sess *SRPServerSession) ParamsForClient(i string) (salt []byte, bPub *big.Int, u *big.Int) {
	return sess.server.salt, sess.bPub, sess.u
}

func (sess *SRPServerSession) ValidateLogin(clientToken []byte) bool {
	var vu big.Int
	vu.Exp(sess.server.v, sess.u, n)

	var avu big.Int
	avu.Mul(sess.aPub, &vu)

	var s big.Int
	s.Exp(&avu, sess.bPriv, n)

	k := ComputeK(&s)

	finalHmac := ComputeFinalHmac(k, sess.server.salt)

	return hmac.Equal(finalHmac, clientToken)
}

func (sess *SRPServerSession) EvilParamsForClient(i string) (salt []byte, bPub *big.Int, u *big.Int) {
	return []byte(""), sess.bPub, big.NewInt(1)
}

func (sess *SRPServerSession) CrackPassword(clientToken []byte) string {
	dict := []string{"foo", "bar", "hello"}
	salt := []byte("")

	for _, guess := range dict {
		x := computeX(guess, salt)

		// s = B**(a + ux) % n
		//   -> we set u = 1
		// s = B**(a + x) % n
		// s = B**a * B**x % n
		//   -> as in DH, B**a = A**b
		// s = A**b * B**x % n

		ab := (&big.Int{}).Exp(sess.aPub, sess.bPriv, n)
		bx := (&big.Int{}).Exp(sess.bPub, x, n)
		ab_bx := (&big.Int{}).Mul(ab, bx)

		s := (&big.Int{}).Mod(ab_bx, n)

		k := ComputeK(s)
		token := ComputeFinalHmac(k, salt)

		if bytes.Equal(token, clientToken) {
			return guess
		}
	}

	panic("failed")
}
