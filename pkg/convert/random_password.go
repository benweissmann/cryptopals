package convert

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

func Dictionary() []string {
	dat, err := os.ReadFile("/usr/share/dict/words")
	if err != nil {
		panic(err.Error())
	}

	lines := strings.Split(string(dat), "\n")

	cleanedLines := []string{}
	for _, line := range lines {
		cleanedLine := strings.TrimSpace(line)
		if len(cleanedLine) > 0 {
			cleanedLines = append(cleanedLines, cleanedLine)
		}
	}

	return cleanedLines
}

func RandomWord() string {
	d := Dictionary()
	return d[rand.N(len(d))]
}

func RandomPassword() string {
	d := Dictionary()

	return fmt.Sprintf("%s%s", d[rand.N(len(d))], d[rand.N(len(d))])
}
