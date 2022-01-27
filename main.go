package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	//"strings"
	"crypto/x509/pkix"
	"time"
	//"io"
)

// functions
// generate
// crl
// receiver (the one I use with vault)

func generate(w http.ResponseWriter, r *http.Request) {
	//fromPkiDER, _ := ioutil.ReadFile("/Users/s2083076/openssl-test/from-pki.der")
	//fromPKI, err := x509.ParseCertificate(fromPkiDER)
	//if err != nil {
	//	panic(err)
	//}
	//jsonFromPKI, _ := json.Marshal(fromPKI)
	//fmt.Fprintf(w, "%s \n\n", jsonFromPKI)

	input := r.URL.Path[10:]
	fmt.Fprintln(w, "Hi there, here is a certificate for "+input+" ! \n \n")

	// load the CA cert and priv (here is self signed but can be any CA)
	certDER, _ := ioutil.ReadFile("/Users/s2083076/openssl-test/val.der")
	keyDER, _ := ioutil.ReadFile("/Users/s2083076/openssl-test/val-key.der")

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	//fmt.Println(cert.PublicKeyAlgorithm)

	key, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		panic(err)
	}
	//fmt.Println(key.E)

	//jsonCertCA, _ := json.Marshal(cert)
	//fmt.Fprintf(w, "%s", jsonCertCA)

	// Build cert template
	temp := &x509.Certificate{}
	temp.IsCA = false
	DNS := []string{input}
	temp.DNSNames = DNS
	temp.SerialNumber = big.NewInt(11)
	temp.SignatureAlgorithm = x509.SHA256WithRSA
	temp.PublicKeyAlgorithm = x509.RSA
	//fmt.Fprintf(w, "%s", temp.DNSNames)

	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	//fmt.Fprintf(w, "%s", newKey.E)

	newCertDER, err := x509.CreateCertificate(rand.Reader, temp, cert, &newKey.PublicKey, key)
	if err != nil {
		panic(err)
	}

	newCert, err := x509.ParseCertificate(newCertDER)
	if err != nil {
		panic(err)
	}

	fmt.Fprintln(w, "")

	//jsonCert, _ := json.Marshal(newCert)
	jsonCert, _ := json.MarshalIndent(newCert, "", "    ")
	fmt.Fprintf(w, "%s", jsonCert)

	fmt.Fprintln(w, "\n\nAnd here is the root CA \n")

	jsonCertCA, _ := json.MarshalIndent(cert, "", "    ")
	fmt.Fprintf(w, "%s", jsonCertCA)

}



func crl(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Signing CRL\n")

	// Gather CA cert and key
	valCertDER, err := ioutil.ReadFile("/Users/s2083076/openssl-test/val2.der")
	if err != nil {
		panic(err)
	}
	valKeyDER, err := ioutil.ReadFile("/Users/s2083076/openssl-test/val-key.der")
	if err != nil {
		panic(err)
	}
	valCert, err := x509.ParseCertificate(valCertDER)
	if err != nil {
		panic(err)
	}
	valKey, err := x509.ParsePKCS1PrivateKey(valKeyDER)
	if err != nil {
		panic(err)
	}

	// Process received data
	resp := r.Body
	//buf := new(strings.Builder)
	//_, _ = io.Copy(buf, resp)
	//fmt.Println(buf.String())
	var revokedCertsAndCrlLifetime RevokedCertsAndCrlLifetime 
	err = json.NewDecoder(resp).Decode(&revokedCertsAndCrlLifetime)
	if err != nil {
		panic(err)
	}

	revokedCerts := revokedCertsAndCrlLifetime.RevokedCerts
	crlLifetime, _ := time.ParseDuration(revokedCertsAndCrlLifetime.CrlLifetime)
	crlBytes, _ := valCert.CreateCRL(rand.Reader, valKey, revokedCerts, time.Now(), time.Now().Add(crlLifetime))
	if err != nil {
		fmt.Printf("error creating new CRL: %s", err)
	}
	
	base64CRL := base64.StdEncoding.EncodeToString(crlBytes)
	fmt.Fprintf(w, "%s", base64CRL)

}

type RevokedCertsAndCrlLifetime struct {
	RevokedCerts  	[]pkix.RevokedCertificate
	CrlLifetime		string
}

// this is the one I am using with Vault !
func receiver(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Signing cert \n")

	// Gather CA cert and key
	valCertDER, err := ioutil.ReadFile("/Users/s2083076/openssl-test/val2.der")
	if err != nil {
		panic(err)
	}
	valKeyDER, err := ioutil.ReadFile("/Users/s2083076/openssl-test/val-key.der")
	if err != nil {
		panic(err)
	}
	valCert, err := x509.ParseCertificate(valCertDER)
	if err != nil {
		panic(err)
	}
	valKey, err := x509.ParsePKCS1PrivateKey(valKeyDER)
	if err != nil {
		panic(err)
	}

	// print issuing CA
	//jsonCert, _ := json.MarshalIndent(valCert, "", "		")
	//fmt.Printf("%s\n", jsonCert)

	// Reveive template and public key for new cert
	resp := r.Body
	var templateAndKey TemplateAndKey
	err = json.NewDecoder(resp).Decode(&templateAndKey)
	if err != nil {
		panic(err)
	}

	// Create new cert
	certBytes, err := x509.CreateCertificate(rand.Reader, &templateAndKey.Template, valCert, &templateAndKey.PublicKey, valKey)
	if err != nil {
		panic(err)
	}
	base64EncodedCert := base64.StdEncoding.EncodeToString(certBytes)
	//fmt.Printf("%s\n\n", base64EncodedCert)
	fmt.Fprintf(w, "%s", base64EncodedCert)
}

type TemplateAndKey struct {
	Template  x509.Certificate
	PublicKey rsa.PublicKey
}

type EncodedKeyring struct {
	MasterKey      []byte
	Keys           []*Key
	RotationConfig KeyRotationConfig
}
type Key struct {
	Term        uint32
	Version     int
	Value       []byte
	InstallTime time.Time
	Encryptions uint64 `json:"encryptions,omitempty"`
}
type KeyRotationConfig struct {
	Disabled      bool
	MaxOperations int64
	Interval      time.Duration
}
type Test struct {
	Aa 	int
	Bb 	int
}

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/generate/", generate)
	mux.HandleFunc("/receive", receiver)
	mux.HandleFunc("/val.com/crl", crl)
	err := http.ListenAndServe(":8080", mux)
	log.Fatal(err)
}
