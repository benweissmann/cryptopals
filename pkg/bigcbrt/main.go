// From https://stackoverflow.com/a/51390715

package bigcbrt

import "math/big"

var (
	n0  = big.NewInt(0)
	n1  = big.NewInt(1)
	n2  = big.NewInt(2)
	n3  = big.NewInt(3)
	n10 = big.NewInt(10)
)

func Cbrt(i *big.Int) (cbrt *big.Int, rem *big.Int) {
	var (
		guess   = new(big.Int).Div(i, n2)
		guessSq = new(big.Int)
		dx      = new(big.Int)
		absDx   = new(big.Int)
		minDx   = new(big.Int).Abs(i)
		cube    = new(big.Int)
		fx      = new(big.Int)
		fxp     = new(big.Int)
		step    = new(big.Int)
	)
	for {
		cube.Exp(guess, n3, nil)
		dx.Sub(i, cube)
		cmp := dx.Cmp(n0)
		if cmp == 0 {
			return guess, n0
		}

		fx.Sub(cube, i)
		guessSq.Exp(guess, n2, nil)
		fxp.Mul(n3, guessSq)
		step.Div(fx, fxp)
		if step.Cmp(n0) == 0 {
			step.Set(n1)
		}

		absDx.Abs(dx)
		switch absDx.Cmp(minDx) {
		case -1:
			minDx.Set(absDx)
		case 0:
			return guess, dx
		}

		guess.Sub(guess, step)
	}
}
