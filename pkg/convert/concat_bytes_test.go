package convert_test

import (
	"bytes"
	"testing"

	"github.com/benweissmann/cryptopals/pkg/convert"
)

func TestConcatBytes(t *testing.T) {
	actual := convert.ConcatBytes([]byte{1, 2, 3}, []byte{4, 5})
	expected := []byte{1, 2, 3, 4, 5}

	if !bytes.Equal(actual, expected) {
		t.Fatalf("Got %v; expected %v", actual, expected)
	}

}
