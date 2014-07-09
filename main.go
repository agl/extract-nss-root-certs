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
package main

import (
	"crypto"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/njones/nss/nss"
)

// The flags that can be used for the command line options
var (
	quietFlg              = flag.Bool("quiet", false, "If set, there will be no output to the display")
	toFilesFlg            = flag.Bool("to-files", false, "If set, individual certificate files will be created in the current directory")
	includeUntrustedFlg   = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")
	ignoreListFilenameFlg = flag.String("ignore-list", "", "File containing a list of certificates to ignore")
)

func main() {
	var display io.Writer

	flag.Parse()

	// Set up the ignore list
	var ignoreList nss.IgnoreList
	if *ignoreListFilenameFlg != "" {
		ignoreListFile, err := os.Open(*ignoreListFilenameFlg)
		if err != nil {
			log.Fatalf("Failed to open ignore-list file: %s", err)
		}
		ignoreList = nss.ParseIgnoreList(ignoreListFile)
		ignoreListFile.Close()
	}

	// Set up the name of the file we are going to read in
	dataFilename := "certdata.txt"
	if len(flag.Args()) == 1 {
		dataFilename = flag.Arg(0)
	} else if len(flag.Args()) > 1 {
		fmt.Printf("Usage: %s [<certdata.txt file>]\n", os.Args[0])
		os.Exit(1)
	}

	file, err := os.Open(dataFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	license, cvsId, objects := nss.ParseInput(file)
	file.Close()

	// Get back the certs from the parsed input
	var nssBlocks []nss.Block
	if *includeUntrustedFlg {
		nssBlocks = nss.AllCertificates(objects, ignoreList)
	} else {
		nssBlocks = nss.TrustedCertificates(objects, ignoreList)
	}

	// Set the display to default to outputting to a screen. But if -quiet is used, then discard
	display = os.Stdout
	if *quietFlg {
		display = ioutil.Discard
	}

	if !*toFilesFlg {
		fmt.Fprint(display, license)
		if len(cvsId) > 0 {
			fmt.Fprintln(display, "CVS_ID", cvsId)
		}
	}

	filenames := make(map[string]bool)
	for _, nssBlock := range nssBlocks {

		label := nssBlock.Label
		x509 := nssBlock.Cert
		block := &pem.Block{Type: "CERTIFICATE", Bytes: x509.Raw}

		// If we are going to output to files then do all of the label stuff
		// This is going to be somewhat slower than if the "if/then" block is
		// outside of the for loop (because it would be evaluated once) however
		// i/o to disk will be a bigger bottle neck, so it's acceptable for
		// code clarity. Or if not... feel free to refactor.
		if *toFilesFlg {

			// Remove all of the leading and trailing "'s and ' 's 
			// that's quotes and spaces...
			label = strings.Trim(label, " \"")

			// The label may contain hex-escaped, UTF-8 characters.
			label = nss.DecodeHexEscapedString(label)
			label = strings.Replace(label, " ", "_", -1)
			label = strings.Replace(label, "/", "_", -1)

			filename := label
			for i := 2; ; i++ {
				if _, ok := filenames[filename]; !ok {
					break
				}

				filename = label + "-" + strconv.Itoa(i)
			}
			filenames[filename] = true

			file, err := os.Create(filename + ".pem")
			if err != nil {
				log.Fatalf("Failed to create output file: %s\n", err)
			}

			pem.Encode(file, block)
			file.Close()
		}

		fmt.Fprintln(display) // Just give a line space between output
		fmt.Fprintln(display, "# Issuer:", nss.Field(x509.Issuer))
		fmt.Fprintln(display, "# Subject:", nss.Field(x509.Subject))
		fmt.Fprintln(display, "# Label:", label)
		fmt.Fprintln(display, "# Serial:", x509.SerialNumber.String())
		fmt.Fprintln(display, "# MD5 Fingerprint:", nss.Fingerprint(crypto.MD5, x509.Raw))
		fmt.Fprintln(display, "# SHA1 Fingerprint:", nss.Fingerprint(crypto.SHA1, x509.Raw))
		fmt.Fprintln(display, "# SHA256 Fingerprint:", nss.Fingerprint(crypto.SHA256, x509.Raw))
		pem.Encode(display, block)
	}
}