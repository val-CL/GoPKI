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

var caCertPath = "root-ca/root.der"
var caKeyPath = "root-ca/root-key.der"


//Input: Common nane
//Output: A certificate and private key for the given common name signed by the CA. Also prints the CA cert.
//Method: GET
//URL: http://127.0.0.1:8080/generate/<common-name>
func generate(w http.ResponseWriter, r *http.Request) {

	fmt.Printf("Generating cert\n")

	input := r.URL.Path[10:]
	fmt.Fprintln(w, "Hi there, here is a certificate for "+input+" ! \n \n")

	// load the CA cert and priv (here is self signed but can be any CA)
	certDER, _ := ioutil.ReadFile(caCertPath)
	keyDER, _ := ioutil.ReadFile(caKeyPath)

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}

	key, err := x509.ParsePKCS1PrivateKey(keyDER)
	if err != nil {
		panic(err)
	}

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


//Input: RevokedCertsAndCrlLifetime {"RevokedCerts":<[]pkix.RevokedCertificate>,"CrlLifetime":<string>}
//Output: Signed CRL base64 encoded, der format
//Method: POST
//Data: {"RevokedCerts":[],"CrlLifetime":"72h0m0s"}
//URL: http://127.0.0.1:8080/val.com/crl
func crl(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Signing CRL\n")

	// Gather CA cert and key
	valCertDER, err := ioutil.ReadFile(caCertPath) //use to be val2.der for testing
	if err != nil {
		panic(err)
	}
	valKeyDER, err := ioutil.ReadFile(caKeyPath)
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

	// Process received data (revoked cert lit and crl lifetime)
	// {"RevokedCerts":<[]pkix.RevokedCertificate>,"CrlLifetime":<string>}
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

	// creating the (signed) CRL
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

//This is the one I am using with Vault !
//Input: TemplateAndKey {"Template":<x509.Certificate>,"PublicKey":<rsa.PublicKey>}
//Output: Signed certificate
func receiver(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Signing cert \n")

	// Gather CA cert and key
	valCertDER, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		panic(err)
	}
	valKeyDER, err := ioutil.ReadFile(caKeyPath)
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

func main() {

	mux := http.NewServeMux()
	mux.HandleFunc("/generate/", generate)
	mux.HandleFunc("/receive", receiver)
	mux.HandleFunc("/root.com/crl", crl)

	fmt.Printf("Listening on port 8080... \n")
	err := http.ListenAndServe(":8080", mux)
	log.Fatal(err)
}