package convert

func ConcatBytes(a []byte, b []byte) []byte {
	out := make([]byte, len(a)+len(b))
	copy(out[:len(a)], a)
	copy(out[len(a):], b)

	return out
}
