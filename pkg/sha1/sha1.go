// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
//
// SHA-1 is cryptographically broken and should not be used for secure
// applications.
package sha1

import (
	"fmt"
)

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "sha\x01"
	marshaledSize = len(magic) + 5*4 + chunk + 8
)

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], BeUint64(b)
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], BeUint32(b)
}

func (d *digest) Inspect() string {
	sum := d.Sum([]byte{})

	return fmt.Sprintf(
		"[h    ] %08x %08x %08x %08x %08x\n[x    ] %s\n[nx   ] %d\n[len  ] %d\n[hash ] %x",
		d.h[0], d.h[1], d.h[2], d.h[3], d.h[4],
		string(d.x[:]),
		d.nx,
		d.len,
		sum,
	)
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

// New returns a new [hash.Hash] computing the SHA1 checksum. The Hash
// also implements [encoding.BinaryMarshaler], [encoding.BinaryAppender] and
// [encoding.BinaryUnmarshaler] to marshal and unmarshal the internal
// state of the hash.
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
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			blockGeneric(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		blockGeneric(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	d.Write(Padding(d.len))

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	BePutUint32(digest[0:], d.h[0])
	BePutUint32(digest[4:], d.h[1])
	BePutUint32(digest[8:], d.h[2])
	BePutUint32(digest[12:], d.h[3])
	BePutUint32(digest[16:], d.h[4])

	return digest
}

func Padding(len uint64) []byte {
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	BePutUint64(padlen[t:], len)

	return padlen
}

func Resume(hash []byte, len uint64) *digest {
	return &digest{
		h: [5]uint32{
			BeUint32(hash[0:4]),
			BeUint32(hash[4:8]),
			BeUint32(hash[8:12]),
			BeUint32(hash[12:16]),
			BeUint32(hash[16:20]),
		},
		nx:  0,
		len: len,
	}
}
