#!/bin/bash

mkdir -p demoCA/newcerts
touch demoCA/index.txt demoCA/index.txt.attr
echo '01' > demoCA/serial

# Generate Root Private Key
certtool --generate-privkey --outfile x509-root-key.pem --rsa

# Generate Root Certificate
certtool --generate-self-signed --template root-template.txt --load-privkey x509-root-key.pem --outfile x509-root-cert.pem

# Generate Intermediate Certificate Key
certtool --generate-privkey --outfile x509-interm-key.pem --rsa

# Generate Intermediate Certificate Signing Request
certtool --generate-request --template interm-template.txt --load-privkey x509-interm-key.pem --outfile x509-interm-cert.csr

# Sign Intermediat Certificate Signing Request
openssl ca -batch -days 365000 -keyfile x509-root-key.pem -cert x509-root-cert.pem -policy policy_anything -config interm.cnf -extensions v3_intermediate -notext -out x509-interm-cert.pem -infiles x509-interm-cert.csr

# Generate Server Key
certtool --generate-privkey --outfile x509-server-key.pem --rsa

# Generate Server Signing Request
certtool --generate-request --template server-template.txt --load-privkey x509-server-key.pem --outfile x509-server-cert.csr

# Sign Server Certificate Request
openssl ca -batch -days 36500 -keyfile x509-interm-key.pem -cert x509-interm-cert.pem -policy policy_anything -notext -out x509-server-cert.pem -infiles x509-server-cert.csr

# == BIBLIOGRAPHY ==
# 1. https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63
# 2. https://gitlab.com/gnuwget/wget/blob/master/tests/certs/create-certs.sh
# 3. https://gitlab.com/gnuwget/wget2/blob/master/tests/certs/README
