package nss

import (
	"crypto"
	_ "crypto/md5"
	"testing"
	//	"crypto/sha1"
	"bufio"
	_ "crypto/sha256"
	"encoding/hex"
	"strings"
)

type fgrpnt struct {
	hashFn crypto.Hash
	data   string
	expect string
}

type hexEsc struct {
	hexEncde string
	expect   string
}

type nssObj struct {
	key   string
	attr  string
	value string
}

func TestParseCkaClassObject(t *testing.T) {
	var objects []*object                               // the return data
	l := 1                                              // line
	s := bufio.NewScanner(strings.NewReader(nssObject)) // scanner

	for s.Scan() {
		l += 1
		line := s.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		words := strings.Fields(line)

		if words[0] == "CKA_CLASS" {

			o := new(object)
			o.startingLine = l
			o.attrs = map[string]attribute{
				words[0]: attribute{
					words[1],
					[]byte(strings.Join(words[2:], " ")),
				},
			}

			l, o = parseCkaClassObject(s, l, o)
			objects = append(objects, o)

			if l != 36 {
				t.Error("Invalid line count for the multi-line octal got:", l, "expected: 36")
			}

			testTable := []nssObj{
				nssObj{"CKA_TOKEN", "CK_BBOOL", "CK_TRUE"},
				nssObj{"CKA_PRIVATE", "CK_BBOOL", "CK_FALSE"},
				nssObj{"CKA_MODIFIABLE", "CK_BBOOL", "CK_FALSE"},
				nssObj{"CKA_LABEL", "UTF8", "\"WoSign China\""},
				nssObj{"CKA_TRUST_SERVER_AUTH", "CK_TRUST", "CKT_NSS_TRUSTED_DELEGATOR"},
				nssObj{"CKA_TRUST_EMAIL_PROTECTION", "CK_TRUST", "CKT_NSS_TRUSTED_DELEGATOR"},
				nssObj{"CKA_TRUST_CODE_SIGNING", "CK_TRUST", "CKT_NSS_TRUSTED_DELEGATOR"},
				nssObj{"CKA_TRUST_STEP_UP_APPROVED", "CK_BBOOL", "CK_FALSE"},
			}

			for _, x := range testTable {
				if aa, ok := o.attrs[x.key]; !ok {
					t.Error("Value not found in attribute list expected:", x.key)
				} else {
					if aa.attrType != x.attr {
						t.Error("Invalid attribute type for key got:", aa.attrType, "expected:", x.attr)
					}

					if string(aa.value) != x.value {
						t.Error("Invalid value type for key got:", string(aa.value), "expected:", x.value)
					}
				}
			}

			testTable2 := []nssObj{
				nssObj{"CKA_CERT_MD5_HASH", "MULTILINE_OCTAL", "78835b521676c4243b8378e8acda9a93"},
				nssObj{"CKA_SERIAL_NUMBER", "MULTILINE_OCTAL", "021050706bcdd813fc1b4e3b3372d211488d"},
				nssObj{"CKA_ISSUER", "MULTILINE_OCTAL", "3046310b300906035504061302434e311a3018060355040a1311576f5369676e204341204c696d69746564311b301906035504030c12434120e6b283e9809ae6a0b9e8af81e4b9a6"},
			}

			for _, x := range testTable2 {
				if aa, ok := o.attrs[x.key]; !ok {
					t.Error("Value not found in attribute list expected:", x.key)
				} else {
					if aa.attrType != x.attr {
						t.Error("Invalid attribute type for key got:", aa.attrType, "expected:", x.attr)
					}
					if hex.EncodeToString(aa.value) != x.value {
						t.Error("Invalid value type for key got:", hex.EncodeToString(aa.value), "expected:", x.value)
					}
				}
			}

		}
	}
}

func TestParseMultiLineOctal(t *testing.T) {
	var b []byte                                                // the return data
	l := 1                                                      // line
	s := bufio.NewScanner(strings.NewReader(nssMultiLineOctal)) // scanner

	l, b = parseMultiLineOctal(s, l)
	if l != 7 {
		t.Error("Invalid line count for the multi-line octal got:", l, "expected: 7")
	}

	if hex.EncodeToString(b) != nssMultiLineOctalExpect {
		t.Error("Invalid octal conversion got:", hex.EncodeToString(b), "expected:", nssMultiLineOctalExpect)
	}
}

func TestParseLicenseBlock(t *testing.T) {
	var license, cvsId string                            // The return data
	l := 1                                               // line
	s := bufio.NewScanner(strings.NewReader(nssLicense)) // scanner

	for s.Scan() {
		l += 1
		line := s.Text()

		if strings.Contains(line, "This Source Code") {
			l, license, cvsId = parseLicenseBlock(s, l)

			if l != 6 { // it adds the extra line
				t.Error("Invalid line count for the multi-line octal got:", l, "expected: 6")
			}

			if strings.TrimSpace(license) != strings.TrimSpace(nssLicenseExpect) {
				t.Error("Invalid parsing for the license got:", license, "expected:", nssLicenseExpect)
			}

			if cvsId != "" {
				t.Error("Invalid parsing for the license cvsId got:", cvsId, "expected: ")
			}

			break
		}
	}
}

func TestParseLicenseBlock2(t *testing.T) {
	var license, cvsId string                            // The return data
	l := 1                                               // line
	s := bufio.NewScanner(strings.NewReader(nssLicense2)) // scanner

	for s.Scan() {
		l += 1
		line := s.Text()

		if strings.Contains(line, "This Source Code") {
			l, license, cvsId = parseLicenseBlock(s, l)

			if l != 7 { // it adds the extra line
				t.Error("Invalid line count for the multi-line octal got:", l, "expected: 7")
			}

			if strings.TrimSpace(license) != strings.TrimSpace(nssLicenseExpect) {
				t.Error("Invalid parsing for the license got:", license, "expected:", nssLicenseExpect)
			}

			if cvsId != cvsIdExpect {
				t.Error("Invalid parsing for the license cvsId got:", cvsId, "expected: ", cvsIdExpect)
			}

			break
		}
	}
}

func TestFingerprint(t *testing.T) {
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
		y := Fingerprint(x.hashFn, []byte(x.data))
		if y != x.expect {
			t.Error("Invalid Fingerprint got:", y, "expected:", x.expect)
		}
	}
}

func TestDecodeHexEscapedString(t *testing.T) {
	testTable := []hexEsc{
		hexEsc{
			"AC Ra\xC3\xADz Certic\xC3\xA1mara S.A.",
			"AC Raíz Certicámara S.A.",
		},
		hexEsc{
			"T\xc3\x9c\x42\xC4\xB0TAK UEKAE K\xC3\xB6k Sertifika Hizmet Sa\xC4\x9Flay\xc4\xb1\x63\xc4\xb1s\xc4\xb1 - S\xC3\xBCr\xC3\xBCm 3",
			"TÜBİTAK UEKAE Kök Sertifika Hizmet Sağlayıcısı - Sürüm 3",
		},
		hexEsc{
			`Hizmet Sa\xC4\x9Flay \\xBC`,
			`Hizmet Sağlay \xBC`,
		},
		hexEsc{
			`\xzk\xbg`,
			`\xzk\xbg`,
		},
	}

	for _, x := range testTable {
		y := DecodeHexEscapedString(x.hexEncde)
		if y != x.expect {
			t.Error("Invalid HexEscape Decode got:", y, "expected:", x.expect)
		}
	}
}

func TestParseIgnoreList(t *testing.T) {
	f := strings.NewReader(nssIgnoreList) // scanner
	p := ParseIgnoreList(f)

	testTable := map[string]string{
		"DigiCert Trusted Root G4": "",
		"E-Guven Kok_Elektronik Sertifika_Hizmet Saglayicisi": "",
		"E-Tugra Certification Authority": "",
		"EBG_Elektronik Sertifika_Hizmet Sağlayıcısı": "Optional Comment: This has UTF-8 characters",
		"EE_Certification Centre Root CA": "",
		"Entrust.net_Premium 2048 Secure Server CA": "",
	}

	for k, v := range testTable {
		if _, ok := p[k]; !ok {
			t.Error("Could not find the parsed value for:", k)
		} else {
			if p[k] != v {
				t.Error("Parsing was incorrect got:", p[k], "expected:", v)
			}
		}
	}
}

func TestField(t *testing.T) {
	// I'm not sure how to create a cert that has multiple organizations or common names to test this out with.	
}

var (
	// An ignore list is just a list of label names, with an optional comment after a #
	nssIgnoreList = `DigiCert Trusted Root G4
E-Guven Kok_Elektronik Sertifika_Hizmet Saglayicisi
E-Tugra Certification Authority
EBG_Elektronik Sertifika_Hizmet Sağlayıcısı # Optional Comment: This has UTF-8 characters
EE_Certification Centre Root CA
Entrust.net_Premium 2048 Secure Server CA`

	nssObject = `# Trust for "WoSign China"
# Issuer: CN=CA ...............,O=WoSign CA Limited,C=CN
# Serial Number:50:70:6b:cd:d8:13:fc:1b:4e:3b:33:72:d2:11:48:8d
# Subject: CN=CA ...............,O=WoSign CA Limited,C=CN
# Not Valid Before: Sat Aug 08 01:00:01 2009
# Not Valid After : Mon Aug 08 01:00:01 2039
# Fingerprint (SHA-256): D6:F0:34:BD:94:AA:23:3F:02:97:EC:A4:24:5B:28:39:73:E4:47:AA:59:0F:31:0C:77:F4:8F:DF:83:11:22:54
# Fingerprint (SHA1): 16:32:47:8D:89:F9:21:3A:92:00:85:63:F5:A4:A7:D3:12:40:8A:D6
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_PRIVATE CK_BBOOL CK_FALSE
CKA_MODIFIABLE CK_BBOOL CK_FALSE
CKA_LABEL UTF8 "WoSign China"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
\026\062\107\215\211\371\041\072\222\000\205\143\365\244\247\323
\022\100\212\326
END
CKA_CERT_MD5_HASH MULTILINE_OCTAL
\170\203\133\122\026\166\304\044\073\203\170\350\254\332\232\223
END
CKA_ISSUER MULTILINE_OCTAL
\060\106\061\013\060\011\006\003\125\004\006\023\002\103\116\061
\032\060\030\006\003\125\004\012\023\021\127\157\123\151\147\156
\040\103\101\040\114\151\155\151\164\145\144\061\033\060\031\006
\003\125\004\003\014\022\103\101\040\346\262\203\351\200\232\346
\240\271\350\257\201\344\271\246
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\002\020\120\160\153\315\330\023\374\033\116\073\063\162\322\021
\110\215
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
CKA_TRUST_CODE_SIGNING CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE`

	nssMultiLineOctal = `\060\106\061\013\060\011\006\003\125\004\006\023\002\103\116\061
\032\060\030\006\003\125\004\012\023\021\127\157\123\151\147\156
\040\103\101\040\114\151\155\151\164\145\144\061\033\060\031\006
\003\125\004\003\014\022\103\101\040\346\262\203\351\200\232\346
\240\271\350\257\201\344\271\246
END`

	nssMultiLineOctalExpect = "3046310b300906035504061302434e311a3018060355040a1311576f5369676e204341204c696d69746564311b301906035504030c12434120e6b283e9809ae6a0b9e8af81e4b9a6"

	nssLicense = `# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#
# certdata.txt
#
# This file contains the object definitions for the certs and other
# information "built into" NSS.
#`
	nssLicenseExpect = `# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.`

	nssLicense2 = `# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
CVS_ID "@(#) $RCSfile$ $Revision$ $Date$"

` 

	cvsIdExpect = `"@(#) $RCSfile$ $Revision$ $Date$"`
)