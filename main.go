package main

import (
	"flag"
	"./nss"
	"fmt"
	"os"
	"log"
)

var (
	includedUntrustedFlag = flag.Bool("include-untrusted", false, "If set, untrusted certificates will also be included in the output")
	toFiles               = flag.Bool("to-files", false, "If set, individual certificate files will be created in the current directory")
	ignoreListFilename    = flag.String("ignore-list", "", "File containing a list of certificates to ignore")
)

func main() {

	flag.Parse()

	inFilename := "certdata.txt"
	if len(flag.Args()) == 1 {
		inFilename = flag.Arg(0)
	} else if len(flag.Args()) > 1 {
		fmt.Printf("Usage: %s [<certdata.txt file>]\n", os.Args[0])
		os.Exit(1)
	}

	ignoreList := make(map[string]string)
	if *ignoreListFilename != "" {
		ignoreListFile, err := os.Open(*ignoreListFilename)
		if err != nil {
			log.Fatalf("Failed to open ignore-list file: %s", err)
		}
		nss.ParseIgnoreList(ignoreListFile)
		ignoreListFile.Close()
	}

	inFile, err := os.Open(inFilename)
	if err != nil {
		log.Fatalf("Failed to open input file: %s", err)
	}

	license, cvsId, objects := nss.ParseInput(inFile)
	inFile.Close()

	if !*toFiles {
		os.Stdout.WriteString(license)
		if len(cvsId) > 0 {
			os.Stdout.WriteString("CVS_ID " + cvsId + "\n")
		}
	}

	nss.IgnoreList = ignoreList
	nss.ToFiles = toFiles
	nss.IncludedUntrustedFlag = includedUntrustedFlag
	nss.OutputTrustedCerts(os.Stdout, objects)
}
