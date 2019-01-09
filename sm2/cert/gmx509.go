package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"

	"github.com/zz/gm/sm2"
)

var (
	oidSM2P256V1           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidSignatureSM3WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func CreateCertificateRequest(template *x509.CertificateRequest, pub *sm2.PublicKey,
	pri *sm2.PrivateKey, userId []byte) (csr []byte, err error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var extensions []pkix.Extension
	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		sanBytes, err := marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return nil, err
		}

		extensions = append(extensions, pkix.Extension{
			Id:    oidExtensionSubjectAltName,
			Value: sanBytes,
		})
	}
	extensions = append(extensions, template.ExtraExtensions...)

	var attributes []pkix.AttributeTypeAndValueSET
	attributes = append(attributes, template.Attributes...)

	if len(extensions) > 0 {
		// specifiedExtensions contains all the extensions that we
		// found specified via template.Attributes.
		specifiedExtensions := make(map[string]bool)

		for _, atvSet := range template.Attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) {
				continue
			}

			for _, atvs := range atvSet.Value {
				for _, atv := range atvs {
					specifiedExtensions[atv.Type.String()] = true
				}
			}
		}

		atvs := make([]pkix.AttributeTypeAndValue, 0, len(extensions))
		for _, e := range extensions {
			if specifiedExtensions[e.Id.String()] {
				// Attributes already contained a value for
				// this extension and it takes priority.
				continue
			}

			atvs = append(atvs, pkix.AttributeTypeAndValue{
				// There is no place for the critical flag in a CSR.
				Type:  e.Id,
				Value: e.Value,
			})
		}

		// Append the extensions to an existing attribute if possible.
		appended := false
		for _, atvSet := range attributes {
			if !atvSet.Type.Equal(oidExtensionRequest) || len(atvSet.Value) == 0 {
				continue
			}

			atvSet.Value[0] = append(atvSet.Value[0], atvs...)
			appended = true
			break
		}

		// Otherwise, add a new attribute for the extensions.
		if !appended {
			attributes = append(attributes, pkix.AttributeTypeAndValueSET{
				Type: oidExtensionRequest,
				Value: [][]pkix.AttributeTypeAndValue{
					atvs,
				},
			})
		}
	}

	asn1Subject := template.RawSubject
	if len(asn1Subject) == 0 {
		asn1Subject, err = asn1.Marshal(template.Subject.ToRDNSequence())
		if err != nil {
			return
		}
	}

	rawAttributes, err := newRawAttributes(attributes)
	if err != nil {
		return
	}

	tbsCSR := tbsCertificateRequest{
		Version: 0, // PKCS #10, RFC 2986
		Subject: asn1.RawValue{FullBytes: asn1Subject},
		PublicKey: publicKeyInfo{
			Algorithm: publicKeyAlgorithm,
			PublicKey: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: len(publicKeyBytes) * 8,
			},
		},
		RawAttributes: rawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return
	}
	tbsCSR.Raw = tbsCSRContents

	var signature []byte
	signature, err = sm2.Sign(pri, userId, tbsCSRContents)
	if err != nil {
		return
	}

	var sigAlgo pkix.AlgorithmIdentifier
	sigAlgo.Algorithm = oidSignatureSM3WithSM2

	return asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: sigAlgo,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	})
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}

// oidNotInExtensions returns whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func marshalPublicKey(pub *sm2.PublicKey) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	publicKeyBytes = pub.GetRawBytes()

	publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
	var paramBytes []byte
	paramBytes, err = asn1.Marshal(oidSM2P256V1)
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	err = nil
	return
}

// newRawAttributes converts AttributeTypeAndValueSETs from a template
// CertificateRequest's Attributes into tbsCertificateRequest RawAttributes.
func newRawAttributes(attributes []pkix.AttributeTypeAndValueSET) ([]asn1.RawValue, error) {
	var rawAttributes []asn1.RawValue
	b, err := asn1.Marshal(attributes)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(b, &rawAttributes)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: failed to unmarshal raw CSR Attributes")
	}
	return rawAttributes, nil
}
