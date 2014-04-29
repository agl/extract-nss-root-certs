Extracting Mozilla's Root Certificates
======================================

When people need a list of root certificates, they often turn to Mozilla's. However, Mozilla doesn't produce a nice list of PEM encoded certificate, rather they keep them in a form which is convenient for NSS to build from:

    https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

Several people have written quick scripts to try and convert this into PEM format, but they often miss something critical: some certificates are explicitly _distrusted_. These include the DigiNotar certificates and the misissued COMODO certificates. If you don't parse the trust records from the NSS data file, then you end up trusting these!

So this is a tool that I wrote for converting the NSS file to PEM format which is also aware of the trust records. It can be built with Go1. See http://golang.org/doc/install.html, but don't pass "-u release" when fetching the repository.

One you have Go installed please do the following:

    % curl https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt
    % go run convert_mozilla_certdata.go > certdata.new

**Other Implementations**

  * Node.js <https://github.com/coolaj86/node-ssl-root-cas>
  * Perl <https://github.com/bagder/curl/blob/master/lib/mk-ca-bundle.pl>
