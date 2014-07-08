Extracting Mozilla's Root Certificates
======================================

When people need a list of root certificates, they often turn to Mozilla's. However, Mozilla doesn't produce a nice list of PEM encoded certificate, rather they keep them in a form which is convenient for NSS to build from:

    https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

Several people have written quick scripts to try and convert this into PEM format, but they often miss something critical: some certificates are explicitly _distrusted_. These include the DigiNotar certificates and the misissued COMODO certificates. If you don't parse the trust records from the NSS data file, then you end up trusting these!

So this is a tool that was written for converting the NSS file to PEM format which is also aware of the trust records. It can be built with Go 1.3. See http://golang.org/doc/install.html, but don't pass "-u release" when fetching the repository.

Once you have Go installed please do the following:

    % curl https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt
    % go run main.go > certdata.new

To use as a library import it like the following:

    import "github.com/njones/nss/nss"

Then use:

    output := nss.ParseInput(file)

This will give you a slice of nss.Blocks that contain the x509 cert along with a UTF-8 encode label. This can then be added to things like a TrustPool http://golang.org/pkg/crypto/x509/#CertPool