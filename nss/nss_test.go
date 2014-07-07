package nss

import (
	"testing"
	"crypto"
	_ "crypto/md5"
//	"crypto/sha1"
	_ "crypto/sha256"
)

type fgrpnt struct{
	hashFn  crypto.Hash
	data     string
	expect   string
}

type hexEsc struct{
	hexEncde string
	expect   string
}

func TestFingerprintString(t *testing.T) {
	testTable := []fgrpnt{
		fgrpnt{
			crypto.MD5,
			"The quick brown fox jumped over the lazy dog",
			"08:a0:08:a0:1d:49:8c:40:4b:0c:30:85:2b:39:d3:b8",
		},
		fgrpnt{
			crypto.SHA1,
			"The quick brown fox jumped over the lazy dog",
			"f6:51:36:40:f3:04:5e:97:68:b2:39:78:56:25:ca:a6:a2:58:88:42",
		},
		fgrpnt{
			crypto.SHA256,
			"The quick brown fox jumped over the lazy dog",
			"7d:38:b5:cd:25:a2:ba:f8:5a:d3:bb:5b:93:11:38:3e:67:1a:8a:14:2e:b3:02:b3:24:d4:a5:fb:a8:74:8c:69",
		},
	}

	for _, x := range testTable {
		y := fingerprintString(x.hashFn, []byte(x.data))
		if y != x.expect {
			t.Error("Invalid Fingerprint got:", y, "expected:", x.expect)
		}
	}
}

func TestUnescapeLabel(t *testing.T) {
	testTable := []hexEsc{
		hexEsc{
			"AC Ra\xC3\xADz Certic\xC3\xA1mara S.A.",
			"AC Raíz Certicámara S.A.",
		},
		hexEsc{
			"T\xc3\x9c\x42\xC4\xB0TAK UEKAE K\xC3\xB6k Sertifika Hizmet Sa\xC4\x9Flay\xc4\xb1\x63\xc4\xb1s\xc4\xb1 - S\xC3\xBCr\xC3\xBCm 3",
			"TÜBİTAK UEKAE Kök Sertifika Hizmet Sağlayıcısı - Sürüm 3",
		},
	}

	for _, x := range testTable {
		y := unescapeLabel(x.hexEncde)
		if y != x.expect {
			t.Error("Invalid HexEscape Decode got:", y, "expected:", x.expect)
		}
	}
}