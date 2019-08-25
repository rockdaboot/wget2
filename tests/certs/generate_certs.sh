# Generate CA private key
certtool --generate-privkey --outfile x509-ca-key.pem --rsa

# Generate CA certificate
certtool --generate-self-signed --load-privkey x509-ca-key.pem --template ca-template.txt --outfile x509-ca-cert.pem

# Generate server private key
certtool --generate-privkey --outfile x509-server-key.pem --rsa

# Generate server certificate
certtool --generate-certificate --load-privkey x509-server-key.pem --template server-template.txt --outfile x509-server-cert.pem --load-ca-certificate x509-ca-cert.pem --load-ca-privkey x509-ca-key.pem

# Generate CRL for the server certificate
certtool --generate-crl --load-ca-privkey x509-ca-key.pem --load-ca-certificate x509-ca-cert.pem --load-certificate x509-server-cert.pem --outfile x509-server-crl.pem --template revoked-template.txt
