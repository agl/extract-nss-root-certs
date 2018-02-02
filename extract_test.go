package nsscerts

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestExtractNSS(t *testing.T) {
	bs, err := ioutil.ReadFile("testdata/certdata.txt")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	r := bytes.NewReader(bs)
	certs, err := List(r, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 133 {
		t.Errorf("got %d certs", len(certs))
	}
}
