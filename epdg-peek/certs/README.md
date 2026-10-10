# epdg-peek certificates

The certificate `AUT_ca_01.crt` is a placeholder certificate, which was copied from the IMS configuration of a smartphone.
It is a GoDaddy root CA, which is probably used by some providers.

Any other certificate can be added to this folder, in order to request the server certificate during `IKE_AUTH`.


Content:

```text
Validity
  Not Before:     03/05/2011 07:00:00 (dd-mm-yyyy hh:mm:ss) (110503070000Z)
  Not After:      03/05/2031 07:00:00 (dd-mm-yyyy hh:mm:ss) (310503070000Z)
Issuer
  C  = US
  ST = Arizona
  L  = Scottsdale
  O  = GoDaddy.com, Inc.
  CN = Go Daddy Root Certificate Authority - G2
Subject
  C  = US
  ST = Arizona
  L  = Scottsdale
  O  = GoDaddy.com, Inc.
  OU = http://certs.godaddy.com/repository/
  CN = Go Daddy Secure Certificate Authority - G2
Fingerprints
  MD5:            96c25031bc0dc35cfba723731e1b4140
  SHA1:           27ac9369faf25207bb2627cefaccbe4ef9c319b8
  SHA256:         973a41276ffd01e027a2aad49e34c37846d3e976ff6a620b6712e33832041aa6
```
