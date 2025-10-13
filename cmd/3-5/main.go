package main

import (
	"fmt"
	"time"

	"github.com/benweissmann/cryptopals/pkg/mt"
)

func main() {
	rand := mt.NewGenerator(uint32(time.Now().Unix()))
	fmt.Println(rand.Rand())
}
