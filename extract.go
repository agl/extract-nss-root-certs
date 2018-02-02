// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

// This is a fork that changes this code into a library that apps can use.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This utility parses Mozilla's certdata.txt and extracts a list of trusted
// certificates in PEM form.
//
// A current version of certdata.txt can be downloaded from:
//   https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt
package nsscerts

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	LatestDownloadURL = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"
)

// Object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type Object struct {
	attrs        map[string]Attribute
	startingLine int // the line number that the object started on.
}

type Attribute struct {
	attrType string
	value    []byte
}

type Config struct {
	// IgnoreList maps from CKA_LABEL values (from the upstream roots file)
	// to an optional comment which is displayed when skipping matching
	// certificates.
	IgnoreList map[string]string

	// Include untrusted certificates
	IncludedUntrustedFlag bool

	// Certificate <TODO>'s
	IgnoreListFilename []string
}

// List reads `in` as a certdata.txt encoded string/file and returns the
// parsed certificates or a non-nil error.
func List(in io.Reader, cfg *Config) ([]*x509.Certificate, error) {
	objects, err := parseObjects(in)
	if err != nil {
		return nil, err
	}
	return findTrustedCerts(cfg, objects)
}

// parseInput parses a certdata.txt file and finds a set of Objects.
func parseObjects(inFile io.Reader) ([]*Object, error) {
	var objects []*Object

	in := bufio.NewReader(inFile)
	var lineNo int

	// Discard anything prior to the license block.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if strings.Contains(line, "This Source Code") {
			break
		}
	}
	// Now collect the license block.
	// certdata.txt from hg.mozilla.org no longer contains CVS_ID.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if strings.Contains(line, "CVS_ID") || len(line) == 0 {
			break
		}
	}

	var currentObject *Object
	var beginData bool

	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if strings.HasPrefix(line, "CVS_ID ") {
			continue
		}
		if line == "BEGINDATA" {
			beginData = true
			continue
		}

		words := strings.Fields(line)
		var value []byte
		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			startingLine := lineNo
			var ok bool
			value, ok = readMultilineOctal(in, &lineNo)
			if !ok {
				return nil, fmt.Errorf("Failed to read octal value starting at line %d", startingLine)
			}
		} else if len(words) < 3 {
			return nil, fmt.Errorf("Expected three or more values on line %d, but found %d", lineNo, len(words))
		} else {
			value = []byte(strings.Join(words[2:], " "))
		}

		if words[0] == "CKA_CLASS" {
			// Start of a new object.
			if currentObject != nil {
				objects = append(objects, currentObject)
			}
			currentObject = new(Object)
			currentObject.attrs = make(map[string]Attribute)
			currentObject.startingLine = lineNo
		}
		if currentObject == nil {
			return nil, fmt.Errorf("Found attribute on line %d which appears to be outside of an object", lineNo)
		}
		currentObject.attrs[words[0]] = Attribute{
			attrType: words[1],
			value:    value,
		}
	}

	if !beginData {
		return nil, fmt.Errorf("Read whole input and failed to find BEGINDATA")
	}

	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return objects, nil
}

// findTrustedCerts collects a series of certificates and their trust records in objects
func findTrustedCerts(cfg *Config, objects []*Object) ([]*x509.Certificate, error) {
	var out []*x509.Certificate

	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")

	for _, cert := range certs {
		derBytes := cert.attrs["CKA_VALUE"].value
		hash := sha1.New()
		hash.Write(derBytes)
		digest := hash.Sum(nil)

		x509, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			continue
		}

		// TODO(agl): wtc tells me that Mozilla might get rid of the
		// SHA1 records in the future and use issuer and serial number
		// to match trust records to certificates (which is what NSS
		// currently uses). This needs some changes to the crypto/x509
		// package to keep the raw names around.

		var trust *Object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest, possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value

		var trusted bool
		switch string(trustType) {
		case "CKT_NSS_NOT_TRUSTED":
			// An explicitly distrusted cert
			trusted = false
		case "CKT_NSS_TRUSTED_DELEGATOR":
			// A cert trusted for issuing SSL server certs.
			trusted = true
		case "CKT_NSS_TRUST_UNKNOWN", "CKT_NSS_MUST_VERIFY_TRUST":
			// A cert not trusted for issuing SSL server certs, but is trusted for other purposes.
			trusted = false
		}

		if !trusted && !cfg.IncludedUntrustedFlag {
			continue
		}

		out = append(out, x509)
	}

	return out, nil
}

// nameToString converts name into a string representation containing the
// CommonName, Organization and OrganizationalUnit.
func nameToString(name pkix.Name) string {
	ret := ""
	if len(name.CommonName) > 0 {
		ret += "CN=" + name.CommonName
	}

	if org := strings.Join(name.Organization, "/"); len(org) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "O=" + org
	}

	if orgUnit := strings.Join(name.OrganizationalUnit, "/"); len(orgUnit) > 0 {
		if len(ret) > 0 {
			ret += " "
		}
		ret += "OU=" + orgUnit
	}

	return ret
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*Object, class string) (out []*Object) {
	for _, object := range in {
		if string(object.attrs["CKA_CLASS"].value) == class {
			out = append(out, object)
		}
	}
	return
}

// readMultilineOctal converts a series of lines of octal values into a slice
// of bytes.
func readMultilineOctal(in *bufio.Reader, lineNo *int) ([]byte, bool) {
	var value []byte

	for line, eof := getLine(in, lineNo); !eof; line, eof = getLine(in, lineNo) {
		if line == "END" {
			return value, true
		}

		for _, octalStr := range strings.Split(line, "\\") {
			if len(octalStr) == 0 {
				continue
			}
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				return nil, false
			}
			value = append(value, byte(v))
		}
	}

	// Missing "END"
	return nil, false
}

// getLine reads the next line from in, aborting in the event of an error.
func getLine(in *bufio.Reader, lineNo *int) (string, bool) {
	*lineNo++
	line, _, err := in.ReadLine()
	if err == io.EOF {
		return "", true
	}
	return string(line), false
}

func fingerprintString(hashFunc crypto.Hash, data []byte) string {
	hash := hashFunc.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	hex := fmt.Sprintf("%x", digest)
	ret := ""
	for len(hex) > 0 {
		if len(ret) > 0 {
			ret += ":"
		}
		todo := 2
		if len(hex) < todo {
			todo = len(hex)
		}
		ret += hex[:todo]
		hex = hex[todo:]
	}

	return ret
}

func isHex(c rune) (value byte, ok bool) {
	switch {
	case c >= '0' && c <= '9':
		return byte(c) - '0', true
	case c >= 'a' && c <= 'f':
		return byte(c) - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return byte(c) - 'A' + 10, true
	}

	return 0, false
}

func appendRune(out []byte, r rune) []byte {
	if r < 128 {
		return append(out, byte(r))
	}

	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], r)
	return append(out, buf[:n]...)
}

// unescapeLabel unescapes "\xab" style hex-escapes.
func unescapeLabel(escaped string) string {
	var out []byte
	var last rune
	var value byte
	state := 0

	for _, r := range escaped {
		switch state {
		case 0:
			if r == '\\' {
				state++
				continue
			}
		case 1:
			if r == 'x' {
				state++
				continue
			}
			out = append(out, '\\')
		case 2:
			if v, ok := isHex(r); ok {
				value = v
				last = r
				state++
				continue
			} else {
				out = append(out, '\\', 'x')
			}
		case 3:
			if v, ok := isHex(r); ok {
				value <<= 4
				value += v
				out = append(out, byte(value))
				state = 0
				continue
			} else {
				out = append(out, '\\', 'x')
				out = appendRune(out, last)
			}
		}
		state = 0
		out = appendRune(out, r)
	}

	switch state {
	case 3:
		out = append(out, '\\', 'x')
		out = appendRune(out, last)
	case 2:
		out = append(out, '\\', 'x')
	case 1:
		out = append(out, '\\')
	}

	return string(out)
}
