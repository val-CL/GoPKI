# GoPKI

INTRO

This project is an application that signs certificates and certificate revokation lists retreiving the key and a CA certificate from a file. The motivation is to connect it with a modified version to Hashicorp Vault (see my contribution to this project on my Github) but it can also be used manually or integrated with another application.


HOW TO DEPLOY/RUN IT

Deploy quick and easy with docker/docker-compose using the included docker-complose yaml file:
$ docker-compose up -d

It can also be deployed manually. It's just a simple Go application.


HOW TO USE IT

Runs of port 8080
Quickly check it's working by visiting http://127.0.0.1:8080/generate with a browser.

List of function and endpoints:

1) Generate

Input: Common name
Output: A certificate and private key for the given common name signed by the CA. Also prints the CA cert.

Method: GET
URL: http://127.0.0.1:8080/generate/<common-name>

Example with curl:
curl http://127.0.0.1:8080/generate/batman

Or just go to http://127.0.0.1:8080/generate/batman with your browser!

2) Receiver

Input: A certificate template with public key
Output: The signed certificaste

Method: POST
URL: http://127.0.0.1:8080/receive
Data (example): {"Template":{"Raw":null,"RawTBSCertificate":null,"RawSubjectPublicKeyInfo":null,"RawSubject":null,"RawIssuer":null,"Signature":null,"SignatureAlgorithm":4,"PublicKeyAlgorithm":0,"PublicKey":null,"Version":0,"SerialNumber":586130151087384648128054229211018977591554317062,"Issuer":{"Country":null,"Organization":null,"OrganizationalUnit":null,"Locality":null,"Province":null,"StreetAddress":null,"PostalCode":null,"SerialNumber":"","CommonName":"","Names":null,"ExtraNames":null},"Subject":{"Country":[],"Organization":[],"OrganizationalUnit":[],"Locality":[],"Province":[],"StreetAddress":[],"PostalCode":[],"SerialNumber":"","CommonName":"www.website.com","Names":null,"ExtraNames":null},"NotBefore":"2022-01-31T19:54:44.7610658Z","NotAfter":"2022-02-03T19:55:14.6625716Z","KeyUsage":21,"Extensions":null,"ExtraExtensions":null,"UnhandledCriticalExtensions":null,"ExtKeyUsage":[1,2],"UnknownExtKeyUsage":null,"BasicConstraintsValid":false,"IsCA":false,"MaxPathLen":0,"MaxPathLenZero":false,"SubjectKeyId":"3LzgL23ad66WkBlQLAUJVZi3Zk8=","AuthorityKeyId":null,"OCSPServer":[],"IssuingCertificateURL":["http://127.0.0.1:8200/v1/pki/ca"],"DNSNames":["www.website.com"],"EmailAddresses":[],"IPAddresses":[],"URIs":[],"PermittedDNSDomainsCritical":false,"PermittedDNSDomains":null,"ExcludedDNSDomains":null,"PermittedIPRanges":null,"ExcludedIPRanges":null,"PermittedEmailAddresses":null,"ExcludedEmailAddresses":null,"PermittedURIDomains":null,"ExcludedURIDomains":null,"CRLDistributionPoints":["http://127.0.0.1:8200/v1/pki/crl"],"PolicyIdentifiers":null},"PublicKey":{"N":26236397680043250646083490267915815869959863296901359129431351246676933040516913788099174201671401771043171673718660906432345378584648318765412568468925333029782695447878693419465233253945241445718994728477727653204332062483156320735601100271173140034471167066039354815546687951412195115026096017323571398332698654774072193920540661213875540106993941984406027806372664761643290194872885622443072890256949726563506277797313789649951559566416378546707147893687704449602375060526507843917880916833024348708568916639444017578029474390457857256740049097497855578807971499238090638995044650557761720039670570120799005425361,"E":65537}}

3) crl

Input: RevokedCertsAndCrlLifetime {"RevokedCerts":<[]pkix.RevokedCertificate>,"CrlLifetime":<string>}
Output: Signed CRL base64 encoded, der format

Method: POST
URL: http://127.0.0.1:8080/val.com/crl
Data (example 1): {"RevokedCerts":[],"CrlLifetime":"72h0m0s"}
Data (example 1): {"revokedCerts":[ {"SerialNumber":586130151087384648128054229211018977591554317062,"RevocationTime":"2022-01-31T20:04:04.8543974Z","Extensions":null}],"CrlLifetime":"72h0m0s"}

Example with curl:
curl --request POST \
    --data '{"RevokedCerts":[],"CrlLifetime":"3600"}' \
    http://127.0.0.1:8080/val.com/crl

To read to output using OpenSSL
1) base64 decode
2) store in a file test.der
3) openssl crl -inform DER -text -noout -in test.der

Example directly doing 1 and 2 after the curl command:
curl --request POST \
    --data '{"RevokedCerts":[],"CrlLifetime":"3600"}' \
    http://127.0.0.1:8080/val.com/crl | base64 -d >> test.der


-----------------------    

Usefull OpenSSL commands

read cert details
$ openssl x509 -in client.pem -text
read a crl
$ openssl crl -in root.crl -text
check a certificate against trusted root CA
$ openssl verify -verbose -CAfile root.pem client.pem
check a certificate against trusted root CA and a CRL
$ cat root.pem root.crl >> chain.pem
$ openssl verify -verbose -crl_check -CAfile chain.pem client.pem
