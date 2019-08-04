#!/bin/bash

# Start Intermediate CA's OCSP server
openssl ocsp -index demoCA/index.txt -ndays 36500 -port 8080 -rsigner x509-interm-cert.pem -rkey x509-interm-key.pem -CA x509-interm-cert.pem -text & ocsp_server=$!

# Save OCSP Stapled Response
openssl ocsp -sha256 -CAfile x509-interm-cert.pem -issuer x509-interm-cert.pem -cert x509-server-cert.pem -url http://127.0.0.1:8080 -noverify -resp_text -respout ocsp_stapled_resp.der

# Kill OCSP Server
kill -9 $ocsp_server

# == BIBLIOGRAPHY ==
# 1. https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63
# 2. https://gitlab.com/gnuwget/wget/blob/master/tests/certs/create-certs.sh
# 3. https://gitlab.com/gnuwget/wget2/blob/master/tests/certs/README
