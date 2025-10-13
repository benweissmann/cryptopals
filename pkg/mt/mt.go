package mt

// #include <stdint.h>

const n = 624
const m = 397
const w = 32
const r = 31
const umask = 0x80000000
const lmask = 0x7fffffff

const a = 0x9908b0df
const u = 11
const s = 7
const t = 15
const l = 18
const b = 0x9d2c5680
const c = 0xefc60000
const f = 1812433253

type MTState struct {
	StateArray [n]uint32 // state vector
	StateIndex int       // index into state vector, 0 <= StateIndex < n
}

func NewGenerator(seed uint32) *MTState {
	state := MTState{}

	state.Seed(seed)

	return &state
}

func (self *MTState) Seed(seed uint32) {
	self.StateArray[0] = seed
	for i := 1; i < n; i++ {
		seed = f*(seed^(seed>>(w-2))) + uint32(i)
		self.StateArray[i] = seed
	}

	self.StateIndex = n
}

func (self *MTState) Rand() uint32 {
	if self.StateIndex >= n {
		self.Twist()
	}

	res := Temper(self.StateArray[self.StateIndex])

	self.StateIndex++

	return res
}

func (self *MTState) Twist() {
	for i := range self.StateArray {
		x := (self.StateArray[i] & umask) | (self.StateArray[(i+1)%n] & lmask)
		xA := x >> 1
		if (x & 1) != 0 {
			xA ^= a
		}

		self.StateArray[i] = self.StateArray[(i+m)%n] ^ xA
	}

	self.StateIndex = 0
}

func Temper(y uint32) uint32 {
	y = rightTemper(y, u)
	y = leftTemper(y, s, b)
	y = leftTemper(y, t, c)
	y = rightTemper(y, l)

	return y
}

func Untemper(y uint32) uint32 {
	y = rightUntemper(y, l)
	y = leftUntemper(y, t, c)
	y = leftUntemper(y, s, b)
	y = rightUntemper(y, u)

	return y
}

func rightTemper(y uint32, shift uint32) uint32 {
	return y ^ (y >> shift)
}

func leftTemper(y uint32, shift uint32, mask uint32) uint32 {
	return y ^ ((y << shift) & mask)
}

func rightUntemper(y uint32, shift uint32) uint32 {
	for i := shift; i < 32; i += shift {
		//fmt.Printf("Iteration %d - shift %d\n", i, shift)

		mask := uint32((1<<shift - 1) << (32 - i))

		//fmt.Printf("[mask      ] %032b\n", mask)
		//fmt.Printf("[untemperer] %032b\n", (y&mask)>>shift)

		y ^= (y & mask) >> shift

		//fmt.Printf("[result    ] %032b\n", y)
	}

	return y
}

func leftUntemper(y uint32, shift uint32, mask uint32) uint32 {
	for i := shift; i < 32; i += shift {
		//fmt.Printf("Iteration %d - shift %d\n", i, shift)

		partMask := uint32((1<<shift - 1) << (i - shift))

		//fmt.Printf("[partMask  ] %032b\n", partMask)
		//fmt.Printf("[untemperer] %032b\n", (y&partMask)<<shift)

		y ^= ((y & partMask) << shift) & mask

		//fmt.Printf("[result    ] %032b\n", y)
	}

	return y
}
