// Copyright 2012 Google Inc. All Rights Reserved.
// Author: agl@chromium.org (Adam Langley)

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
package nss

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
)

// Block is the exported type from this lib. It has the label and the cert in Binary form
type Block struct {
	Label string
	Cert  *x509.Certificate
}

// IgnoreList is where all of the strings for certs to ignore a held.
// it maps from CKA_LABEL values (from the upstream roots file)
// to an optional comment which is displayed when skipping matching
// certificates.
type IgnoreList map[string]string

// object represents a collection of attributes from the certdata.txt file
// which are usually either certificates or trust records.
type object struct {
	attrs        map[string]attribute
	startingLine int // the line number that the object started on.
}

// attribute are the attributes for a CKA_CLASS object
type attribute struct {
	attrType string
	value    []byte
}

// filterObjectsByClass returns a subset of in where each element has the given
// class.
func filterObjectsByClass(in []*object, class string) (out []*object) {
	for _, o := range in {
		if string(o.attrs["CKA_CLASS"].value) == class {
			out = append(out, o)
		}
	}

	return
}

// parseLicenseBlock parses the license block out of the current scan of text
func parseLicenseBlock(in *bufio.Scanner, ln int) (lineNo int, license, cvsId string) {
	license += in.Text() + "\n" // Add this line to the license string

	// Loop through the next lines until we get to an blank line
	for in.Scan() {

		// Advance the line count and grab the line
		ln += 1
		line := in.Text()

		// Check to see if there is a CVS_ID line within the license
		if strings.HasPrefix(line, "CVS_ID ") {
			cvsId = line[7:]
			continue
		}

		// If the line is blank then we can exit out of the license loop
		if len(line) == 0 {
			break
		}
		license += line + "\n" // Add this line to the license string.
	}

	return ln, license, cvsId
}

// parseMultiLineOctal parses the octal encoding which can span multiple 
// lines out of the blocks as binary data
func parseMultiLineOctal(in *bufio.Scanner, ln int) (lineNo int, value []byte) {
	// Loop through the next lines (inner-loop 2)
	for in.Scan() {

		// Advance the line count and grab the line
		ln += 1
		line := in.Text()

		// If we've hit the end of the block then break out of (inner-loop 2) 
		// and go back to inner-loop 1
		if line == "END" {
			break
		}

		// Split all of the octal encodings for the line out.
		for _, octalStr := range strings.Split(line, `\`) {
			if len(octalStr) == 0 {
				continue
			}

			// Parse the string value to a int8 (byte) value
			v, err := strconv.ParseUint(octalStr, 8, 8)
			if err != nil {
				log.Fatalf("error converting octal string '%s' on line %d", octalStr, lineNo)
			}

			// Append all of the bytes
			value = append(value, byte(v))
		}
	}

	return ln, value
}

// parseCkaClassObject parses the CKA_CLASS blocks as an object
func parseCkaClassObject(in *bufio.Scanner, ln int, cka *object) (lineNo int, o *object) {
	// Loop through the lines of the CKA_CLASS and add to the object
	for in.Scan() {

		ln += 1
		line := in.Text()

		// This signifies the last octal block of an object
		if len(line) == 0 || line[0] == '#' {
			break
		}

		var value []byte
		words := strings.Fields(line)

		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			ln, value = parseMultiLineOctal(in, ln)
		} else if len(words) < 3 {
			log.Fatalf("Expected three or more values on line %d, but found %d", lineNo, len(words))
		} else {
			lineNo += 1
			value = []byte(strings.Join(words[2:], " "))
		}

		cka.attrs[words[0]] = attribute{words[1], value}
	}

	return ln, cka
}

// ParseIgnoreList parses the ignore-list file into IgnoreList
func ParseIgnoreList(file io.Reader) (ignoreList IgnoreList) {
	ignoreList = make(IgnoreList)
	in := bufio.NewScanner(file)

	for in.Scan() {
		line := in.Text()
		if split := strings.SplitN(line, "#", 2); len(split) == 2 {
			// this line has an additional comment
			ignoreList[strings.TrimSpace(split[0])] = strings.TrimSpace(split[1])
		} else {
			ignoreList[line] = ""
		}
	}

	return
}

// ParseInput parses a certdata.txt file into it's license blob, the CVS id (if
// included) and a set of Objects.
func ParseInput(file io.Reader) (license, cvsId string, objects []*object) {
	in := bufio.NewScanner(file)

	var lineNo int
	var hasLicense bool
	var hasBeginData bool

	for in.Scan() {

		lineNo += 1
		line := in.Text()

		// Collect the license block
		// Loop until we get the line "This Source Code" ...
		if strings.Contains(line, "This Source Code") {
			hasLicense = true // We have found a license, so set this check to true.
			lineNo, license, cvsId = parseLicenseBlock(in, lineNo)
		}

		// Loop until we get to the line BEGINDATA
		if line == "BEGINDATA" {
			hasBeginData = true

			// Now finish the scanning of the document here (inner-loop 1). We shouldn't need to go back to the outer loop
			for in.Scan() {

				// Advance the line count and grab the line
				lineNo += 1
				line := in.Text()

				// Skip all of the comments
				if len(line) == 0 || line[0] == '#' {
					continue
				}

				// See what words are on this line
				words := strings.Fields(line)

				// CKA_CLASS are the magic words to set up an object, so lets start a new object
				if words[0] == "CKA_CLASS" {

					ckaClass := new(object)
					ckaClass.startingLine = lineNo
					ckaClass.attrs = map[string]attribute{
						words[0]: attribute{
							words[1],
							[]byte(strings.Join(words[2:], " ")),
						},
					}

					lineNo, ckaClass = parseCkaClassObject(in, lineNo, ckaClass)
					objects = append(objects, ckaClass)
				}
			}
		}
	}

	if !hasLicense {
		log.Fatalf("Read whole input and failed to find beginning of license")
	}

	if !hasBeginData {
		log.Fatalf("Read whole input and failed to find BEGINDATA")
	}

	return
}

// TrustedCertificates returns all of the parsed objects that have an 
// associated trust certificate. An optional ignoreList can be passed
// along. If more than one is passed, then it is ignored.
func TrustedCertificates(objects []*object, il ...IgnoreList) []Block {
	ignoreList := make(map[string]string)
	if len(il) > 0 {
		ignoreList = il[0]
	}

	return certs(objects, ignoreList, false)
}

// AllCertificates returns all of the parsed objects regardless of whether  
// there is an associated trust certificate. An optional ignoreList can 
// be passed along. If more than one is passed, then it is ignored.
func AllCertificates(objects []*object, il ...IgnoreList) []Block {
	ignoreList := make(map[string]string)
	if len(il) > 0 {
		ignoreList = il[0]
	}

	return certs(objects, ignoreList, true)
}

// certs writes a series of PEM encoded certificates to out by
// finding certificates and their trust records in objects.
// The output is a slice of Blocks that include the label and x509 cert
func certs(objects []*object, ignoreList IgnoreList, includeUntrusted bool) (blocks []Block) {
	certs := filterObjectsByClass(objects, "CKO_CERTIFICATE")
	trusts := filterObjectsByClass(objects, "CKO_NSS_TRUST")

	for _, cert := range certs {
		derBytes := cert.attrs["CKA_VALUE"].value
		hash := sha1.New()
		hash.Write(derBytes)
		digest := hash.Sum(nil)

		label := string(cert.attrs["CKA_LABEL"].value)
		if comment, present := ignoreList[strings.Trim(label, "\"")]; present {
			var sep string
			if len(comment) > 0 {
				sep = ": "
			}
			log.Printf("Skipping explicitly ignored certificate: %s%s%s", label, sep, comment)
			continue
		}

		x509, err := x509.ParseCertificate(derBytes)
		if err != nil {
			// This is known to occur because of a broken certificate in NSS.
			// https://bugzilla.mozilla.org/show_bug.cgi?id=707995
			log.Printf("Failed to parse certificate starting on line %d: %s", cert.startingLine, err)
			continue
		}

		// TODO(agl): wtc tells me that Mozilla might get rid of the
		// SHA1 records in the future and use issuer and serial number
		// to match trust records to certificates (which is what NSS
		// currently uses). This needs some changes to the crypto/x509
		// package to keep the raw names around.

		var trust *object
		for _, possibleTrust := range trusts {
			if bytes.Equal(digest, possibleTrust.attrs["CKA_CERT_SHA1_HASH"].value) {
				trust = possibleTrust
				break
			}
		}

		if trust == nil {
			log.Fatalf("No trust found for certificate object starting on line %d (sha1: %x)", cert.startingLine, digest)
		}

		trustType := trust.attrs["CKA_TRUST_SERVER_AUTH"].value
		if len(trustType) == 0 {
			log.Fatalf("No CKA_TRUST_SERVER_AUTH found in trust starting at line %d", trust.startingLine)
		}

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
		default:
			log.Fatalf("Unknown trust value '%s' found for trust record starting on line %d", trustType, trust.startingLine)
		}

		if !trusted && !includeUntrusted {
			continue
		}

		blocks = append(blocks, Block{label, x509})
	}

	return
}

// Field converts name into a string representation containing the
// CommonName, Organization and OrganizationalUnit.
func Field(name pkix.Name) string {
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

// Fingerprint returns the passed in hash (MD5, SHA1, SHA256) in a
// fingerprint format (i.e. AA:0B:DC:... )
func Fingerprint(hashFunc crypto.Hash, data []byte) string {
	hash := hashFunc.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	// Print out Hex numbers with a space, then replace that space with a colon.
	return strings.Replace(fmt.Sprintf("% x", digest), " ", ":", -1)
}

// DecodeHexEscapedString returns unescaped "\xab" style hex-escape strings
func DecodeHexEscapedString(s string) string {
	var out []byte

	// Loop through one byte at a time for the length of a string
	for i:=0;i < len(s);i++ {

		// Check to see if we are escaping a slash
		if i+2 < len(s) && s[i:i+2] == `\\` {
			out = append(out, s[i])
			i += 1
			continue
		}

		// Check to see if we can have at least 4 bytes to work with, if so check to see if the first two are "\x"
		if i+4 < len(s) && s[i:i+2] == `\x` {
			r, err := hex.DecodeString(s[i+2:i+4])
			if err == nil {
				// No errors, so append the byte, and skip ahead 4 bytes.
				out = append(out, r[0])
				i += 3 // the fourth one is added on the loop (i++)
				continue
			}
		}

		// otherwise append the byte to the string and keep moving
		out = append(out, s[i])
	}

	return string(out)
}