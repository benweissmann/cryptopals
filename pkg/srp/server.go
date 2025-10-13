package srp

import (
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
}

func (server *SRPServer) NewSession() (serverSession *SRPServerSession) {
	bPriv, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(err)
	}

	var gb big.Int
	gb.Exp(big.NewInt(g), bPriv, n)

	var kv big.Int
	kv.Mul(big.NewInt(k), server.v)

	var bPub big.Int
	bPub.Add(&kv, &gb)

	bPub.Mod(&bPub, n)

	return &SRPServerSession{
		server: server,
		bPriv:  bPriv,
		bPub:   &bPub,
	}
}

func (sess *SRPServerSession) ParamsForClient(i string) (salt []byte, bPub *big.Int) {
	if i != sess.server.i {
		panic(fmt.Errorf("Mismatched i: client %s ; server %s", i, sess.server.i))
	}

	return sess.server.salt, sess.bPub
}

func (sess *SRPServerSession) ValidateLogin(clientToken []byte, aPub *big.Int) bool {
	u := computeU(aPub, sess.bPub)

	var vu big.Int
	vu.Exp(sess.server.v, u, n)

	var avu big.Int
	avu.Mul(aPub, &vu)

	var s big.Int
	s.Exp(&avu, sess.bPriv, n)

	k := ComputeK(&s)

	finalHmac := ComputeFinalHmac(k, sess.server.salt)

	return hmac.Equal(finalHmac, clientToken)
}
