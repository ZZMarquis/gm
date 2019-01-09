package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/zz/gm/sm2"
)

func TestX500Name(t *testing.T) {
	name := new(pkix.Name)
	name.CommonName = "ID=Mock Root CA"
	name.Country = []string{"CN"}
	name.Province = []string{"Beijing"}
	name.Locality = []string{"Beijing"}
	name.Organization = []string{"org.zz"}
	name.OrganizationalUnit = []string{"org.zz"}
	fmt.Println(name.String())
}

func TestCreateCertificateRequest(t *testing.T) {
	pri, pub, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:    oidExtensionSubjectAltName,
				Value: sanContents,
			},
		},
	}

	derBytes, err := CreateCertificateRequest(&template, pub, pri, nil)
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile("sample.csr", derBytes, 0644)
}
