# GoPKI

Deploy quick and easy with docker-compose !
docker-compose up -d

Runs of port 8080
val.der is a self signed certificate that we use as a PKI CA cert
val-key.der is the private key for val.der
what is val2.der ??

3 functions:

1) Generate

Input: Common nane
Output: A certificate and private key for the given common name signed by the CA. Also prints the CA cert.

Method: GET
URL: http://127.0.0.1:8080/generate/<common-name>

Example with curl:
curl http://127.0.0.1:8080/generate/batman

Or just go to http://127.0.0.1:8080/generate/batman with your browser!

2) Receiver

Method: POST
URL: http://127.0.0.1:8080/receive

3) crl

Input: RevokedCertsAndCrlLifetime {"RevokedCerts":<[]pkix.RevokedCertificate>,"CrlLifetime":<string>}
Output: Signed CRL base64 encoded, der format

Method: POST
Data: {"RevokedCerts":<[]pkix.RevokedCertificate>,"CrlLifetime":<string>}
URL: http://127.0.0.1:8080/val.com/crl

Example with curl:
curl --request POST \
    --data '{"RevokedCerts":[],"CrlLifetime":"3600"}' \
    http://127.0.0.1:8080/val.com/crl | base64 -d >> test2.der

To read to output using OpenSSL
1) base64 decode
2) store in a file test.der
3) openssl crl -inform DER -text -noout -in test.der

Example directly doing 1 and 2 after the curl command:
curl --request POST \
    --data '{"RevokedCerts":[],"CrlLifetime":"3600"}' \
    http://127.0.0.1:8080/val.com/crl | base64 -d >> test.der
