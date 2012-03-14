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
//   https://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1
package main

import (
	"bufio"
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
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

var includedUntrustedFlag = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")

func main() {
	flag.Parse()

	inFilename := "certdata.txt"
	if len(flag.Args()) == 1 {
		inFilename = flag.Arg(0)
	} else if len(flag.Args()) > 1 {
		fmt.Printf("Usage: %s [<certdata.txt file>]\n", os.Args[0])
		os.Exit(1)
	}

	inFile, err := os.Open(inFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	license, cvsId, objects := parseInput(inFile)
	inFile.Close()

	os.Stdout.WriteString(license)
	if len(cvsId) > 0 {
		os.Stdout.WriteString("CVS_ID " + cvsId + "\n")
	}

	outputTrustedCerts(os.Stdout, objects)
}

// parseInput parses a certdata.txt file into it's license blob, the CVS id (if
// included) and a set of Objects.
func parseInput(inFile io.Reader) (license, cvsId string, objects []*Object) {
	in := bufio.NewReader(inFile)
	var lineNo int

	// Discard anything prior to the license block.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if strings.Contains(line, "BEGIN LICENSE BLOCK") {
			license += line
			license += "\n"
			break
		}
	}
	if len(license) == 0 {
		log.Fatalf("Read whole input and failed to find beginning of license")
	}
	// Now collect the license block.
	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		license += line
		license += "\n"
		if strings.Contains(line, "END LICENSE BLOCK") {
			break
		}
	}
	if !strings.Contains(license, "END LICENSE BLOCK") {
		log.Fatalf("Read whole input and failed to find end of license")
	}

	var currentObject *Object

	for line, eof := getLine(in, &lineNo); !eof; line, eof = getLine(in, &lineNo) {
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if strings.HasPrefix(line, "CVS_ID ") {
			cvsId = line[7:]
			continue
		}
		if line == "BEGINDATA" {
			continue
		}

		words := strings.Fields(line)
		var value []byte
		if len(words) == 2 && words[1] == "MULTILINE_OCTAL" {
			startingLine := lineNo
			var ok bool
			value, ok = readMultilineOctal(in, &lineNo)
			if !ok {
				log.Fatalf("Failed to read octal value starting at line %d", startingLine)
			}
		} else if len(words) < 3 {
			log.Fatalf("Expected three or more values on line %d, but found %d", lineNo, len(words))
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
			log.Fatalf("Found attribute on line %d which appears to be outside of an object", lineNo)
		}
		currentObject.attrs[words[0]] = Attribute{
			attrType: words[1],
			value:    value,
		}
	}

	if currentObject != nil {
		objects = append(objects, currentObject)
	}

	return
}

// outputTrustedCerts writes a series of PEM encoded certificates to out by
// finding certificates and their trust records in objects.
func outputTrustedCerts(out *os.File, objects []*Object) {
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
			log.Printf("Failed to parse certificate starting on line %d: %s", cert.startingLine, err)
			continue
		}

		label := string(cert.attrs["CKA_LABEL"].value)

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

		if (!trusted && !*includedUntrustedFlag) {
			continue
		}

		out.WriteString("\n")
		if !trusted {
			out.WriteString("# NOT TRUSTED FOR SSL\n")
		}
		out.WriteString("# Issuer: " + nameToString(x509.Issuer) + "\n")
		out.WriteString("# Subject: " + nameToString(x509.Subject) + "\n")
		out.WriteString("# Label: " + label + "\n")
		out.WriteString("# Serial: " + x509.SerialNumber.String() + "\n")
		out.WriteString("# MD5 Fingerprint: " + fingerprintString(crypto.MD5, x509.Raw) + "\n")
		out.WriteString("# SHA1 Fingerprint: " + fingerprintString(crypto.SHA1, x509.Raw) + "\n")
		out.WriteString("# SHA256 Fingerprint: " + fingerprintString(crypto.SHA256, x509.Raw) + "\n")
		pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	}
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
				log.Printf("error converting octal string '%s' on line %d", octalStr, *lineNo)
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
	line, isPrefix, err := in.ReadLine()
	if err == io.EOF {
		return "", true
	}
	if err != nil {
		log.Fatalf("I/O error while reading input: %s", err)
	}
	if isPrefix {
		log.Fatalf("Line too long while reading line %d", *lineNo)
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
