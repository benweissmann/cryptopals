// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md4 implements the MD4 hash algorithm as defined in RFC 1320.
//
// Deprecated: MD4 is cryptographically broken and should only be used
// where compatibility with legacy systems, not security, is the goal. Instead,
// use a secure hash like SHA-256 (from crypto/sha256).
package md4

import (
	"fmt"
)

// The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() *digest {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(digest)
	*d = *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	d.Write(Padding(d.len))

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

func readLittleEndian(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func Resume(hash []byte, len uint64) *digest {
	return &digest{
		s: [4]uint32{
			readLittleEndian(hash[0:4]),
			readLittleEndian(hash[4:8]),
			readLittleEndian(hash[8:12]),
			readLittleEndian(hash[12:16]),
		},
		nx:  0,
		len: len,
	}
}

func Padding(len uint64) []byte {
	out := []byte{}

	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		out = append(out, tmp[0:56-len%64]...)
	} else {
		out = append(out, tmp[0:64+56-len%64]...)
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}

	out = append(out, tmp[0:8]...)

	return out
}

func (d *digest) Inspect() string {
	sum := d.Sum([]byte{})

	return fmt.Sprintf(
		"[h    ] %08x %08x %08x %08x\n[x    ] %s\n[nx   ] %d\n[len  ] %d\n[hash ] %x",
		d.s[0], d.s[1], d.s[2], d.s[3],
		string(d.x[:]),
		d.nx,
		d.len,
		sum,
	)
}
