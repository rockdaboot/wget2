README
===

## Files
* ca-template.txt: Template for generating CA certificate
* server-template.txt: Template for server certificate

* x509-*-key.pem: Private Keys
* x509-*-cert.pem: TLS Certificate

* x509-server-crl.pem: CRL for server

# Generating Required Files
```
$ bash generate.sh
```
The script would automatically generate the required files. For generating the CRL, two inputs might be needed:
```
Generating a signed CRL...
Update times.
The certificate will expire in (days): -1
CRL Number (default: 6729013129445461199):

X.509 Certificate Revocation List Information:
        Version: 2
        Issuer: O=gnuwget,OU=Wget,CN=root
        Update dates:
                Issued: Sun Aug 25 08:07:34 UTC 2019
                Next at: Fri Dec 31 23:59:59 UTC 9999
        Extensions:
                Authority Key Identifier (not critical):
                        98a8a7e3ee7d4ae507ac83e6aa666c33a8e0479d
                CRL Number (not critical): 5d6241ca15894ccf
        Revoked certificates (1):
                Serial Number (hex): 5d6163651ae09795623b877c
                Revoked at: Sun Aug 25 08:07:34 UTC 2019
        Signature Algorithm: RSA-SHA256
        Signature:
                68:93:d9:c6:a5:ec:ad:45:f2:24:27:da:fd:7b:ff:ee
                26:4f:47:1c:a3:ec:bc:54:d1:2a:64:04:0f:cb:40:43
                33:ec:14:f7:80:0a:9f:ff:12:1a:7f:a1:c4:18:1b:5f
                4f:b7:24:d5:08:b3:d5:19:d6:d5:51:e4:d8:83:be:1e
                56:59:49:21:64:f2:df:4e:c7:24:11:50:38:c6:b6:e4
                35:3c:55:d7:24:86:ba:86:e2:a8:8e:fc:40:c9:cd:00
                96:20:f1:2e:eb:90:a0:b8:f7:e0:97:d1:b8:a8:a0:8a
                7d:fa:7f:37:d8:82:a3:40:98:24:ab:26:6d:b9:8f:a7
                94:92:5a:99:13:85:19:c2:f4:7a:53:b7:2b:e1:6c:32
                b1:e5:90:fd:d6:1e:ab:0d:df:39:0c:40:85:a4:41:92
                1b:94:19:17:92:a7:2a:8d:69:cd:80:05:2d:a0:c0:5b
                ce:8a:be:75:f3:32:22:de:09:41:9f:f4:56:8e:a2:b1
                08:8c:79:36:f5:c8:46:2f:e3:f3:e0:3a:19:b2:61:a1
                1d:63:01:25:4d:f5:a9:c1:e7:2f:a8:b1:3b:0e:10:55
                af:fc:4f:3c:0b:7b:f7:26:0b:8b:3b:1c:d3:d7:d5:b2
                69:63:3c:68:cd:52:38:b2:02:2e:92:31:d4:cd:70:29
                4c:ae:e4:8b:60:48:15:70:5c:21:d6:79:80:db:1d:81
                29:02:3d:1d:63:5e:d4:3f:85:2e:62:67:5f:09:2c:e7
                86:87:9f:26:3c:82:e5:f1:25:82:d8:27:a4:a1:3c:34
                63:94:95:06:94:fa:4d:0b:9b:73:1e:00:48:34:29:64
                d0:0b:6f:ff:58:d7:01:b6:ca:8b:d4:8f:90:87:35:b5
                19:5e:1d:ee:78:db:55:3f:6e:8f:91:5c:1d:f4:02:80
                f9:b0:35:4b:86:d0:ad:0c:23:5e:fd:6c:b4:3c:8d:a0
                a8:74:bf:68:1c:8d:9c:13:8b:bb:86:bc:94:fe:83:33
```
