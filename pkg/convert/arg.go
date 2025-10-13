package convert

import (
	"fmt"
	"os"
	"strings"
)

func MustLoadHexLines() [][]byte {
	if len(os.Args) < 2 {
		panic(fmt.Sprintf("Usage: %s path-to-hex-lines.txt", os.Args[0]))
	}

	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err.Error())
	}

	lines := strings.Split(string(dat), "\n")

	decodedLines := [][]byte{}
	for _, line := range lines {
		cleanedLine := strings.TrimSpace(line)
		if len(cleanedLine) > 0 {
			decodedLines = append(decodedLines, MustParseHex(cleanedLine))
		}
	}

	return decodedLines
}

func MustLoadBase64Blob() []byte {
	if len(os.Args) < 2 {
		panic(fmt.Sprintf("Usage: %s path-to-base64.txt", os.Args[0]))
	}

	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err.Error())
	}

	return MustParseBase64(string(dat))
}

func MustLoadBas64Lines() [][]byte {
	if len(os.Args) < 2 {
		panic(fmt.Sprintf("Usage: %s path-to-hex-lines.txt", os.Args[0]))
	}

	dat, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err.Error())
	}

	lines := strings.Split(string(dat), "\n")

	decodedLines := [][]byte{}
	for _, line := range lines {
		if len(line) > 0 {
			decodedLines = append(decodedLines, MustParseBase64(line))
		}
	}

	return decodedLines
}
