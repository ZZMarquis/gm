package cert

import (
	"crypto/x509/pkix"
	"fmt"
	"testing"
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
