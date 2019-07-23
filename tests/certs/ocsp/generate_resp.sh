# Start root CA's OCSP Responder
openssl ocsp -index demoCA/index.txt -port 8080 -rsigner x509-root-cert.pem -rkey x509-root-key.pem -CA x509-root-cert.pem -text & ocsp_server=$!

# Save OCSP OK Response
openssl ocsp -sha256 -CAfile x509-root-cert.pem -issuer x509-root-cert.pem -cert x509-interm-cert.pem -url http://127.0.0.1:8080 -noverify -resp_text -respout ocsp_resp_ok.der

sleep 1;

# Kill OCSP Server
kill -9 $ocsp_server

# Revoke Intermediate Certificate
openssl ca -keyfile x509-root-key.pem -cert x509-root-cert.pem -revoke x509-interm-cert.pem 

# Start root CA's OCSP Responder
openssl ocsp -index demoCA/index.txt -port 8080 -rsigner x509-root-cert.pem -rkey x509-root-key.pem -CA x509-root-cert.pem -text & ocsp_server=$!

# Save OCSP OK Response
openssl ocsp -sha256 -CAfile x509-root-cert.pem -issuer x509-root-cert.pem -cert x509-interm-cert.pem -url http://127.0.0.1:8080 -noverify -resp_text -respout ocsp_resp_revoked.der

sleep 1;

# Kill OCSP Server
kill -9 $ocsp_server

# == BIBLIOGRAPHY ==
# 1. https://medium.com/@bhashineen/create-your-own-ocsp-server-ffb212df8e63
# 2. https://gitlab.com/gnuwget/wget/blob/master/tests/certs/create-certs.sh
# 3. https://gitlab.com/gnuwget/wget2/blob/master/tests/certs/README
