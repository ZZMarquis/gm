package cert

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ZZMarquis/gm/cryptobyte"
	cryptobyte_asn1 "github.com/ZZMarquis/gm/cryptobyte/asn1"
	"github.com/ZZMarquis/gm/sm2"
)

var (
	oidSM2P256V1           = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
	oidSignatureSM3WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}

	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
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
	publicKeyBytes = pub.GetUnCompressBytes()

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

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*x509.CertificateRequest, error) {
	var csr certificateRequest

	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificateRequest(&csr)
}

func parseCertificateRequest(in *certificateRequest) (*x509.CertificateRequest, error) {
	out := &x509.CertificateRequest{
		Raw:                      in.Raw,
		RawTBSCertificateRequest: in.TBSCSR.Raw,
		RawSubjectPublicKeyInfo:  in.TBSCSR.PublicKey.Raw,
		RawSubject:               in.TBSCSR.Subject.FullBytes,

		Signature:          in.SignatureValue.RightAlign(),
		SignatureAlgorithm: 0, //与x509.go里的实现不一样，因为这里都是固定了使用SM3WithSM2

		PublicKeyAlgorithm: 0, //与x509.go里的实现不一样，因为这里都是固定了使用EC公钥

		Version:    in.TBSCSR.Version,
		Attributes: parseRawAttributes(in.TBSCSR.RawAttributes),
	}

	if !oidSignatureSM3WithSM2.Equal(in.SignatureAlgorithm.Algorithm) {
		return nil, errors.New("x509: illegal signature algorithm OID")
	}
	if !oidPublicKeyECDSA.Equal(in.TBSCSR.PublicKey.Algorithm.Algorithm) {
		return nil, errors.New("x509: illegal publick key algorithm OID")
	}

	var err error
	out.PublicKey, err = parsePublicKey(&in.TBSCSR.PublicKey)
	if err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	out.Subject.FillFromRDNSequence(&subject)

	if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil {
		return nil, err
	}

	for _, extension := range out.Extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(extension.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

func parsePublicKey(keyData *publicKeyInfo) (interface{}, error) {
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after SM2 parameters")
	}
	if !oidSM2P256V1.Equal(*namedCurveOID) {
		return nil, errors.New("x509: CurveOID is not the OID of SM2P256V1")
	}

	curve := sm2.GetSm2P256V1()
	x, y := elliptic.Unmarshal(curve, keyData.PublicKey.RightAlign())
	if x == nil || y == nil {
		return nil, errors.New("x509: Unmarshal PublicKey failed")
	}
	pub := &sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}

// parseRawAttributes Unmarshals RawAttributes intos AttributeTypeAndValueSETs.
func parseRawAttributes(rawAttributes []asn1.RawValue) []pkix.AttributeTypeAndValueSET {
	var attributes []pkix.AttributeTypeAndValueSET
	for _, rawAttr := range rawAttributes {
		var attr pkix.AttributeTypeAndValueSET
		rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		// Ignore attributes that don't parse into pkix.AttributeTypeAndValueSET
		// (i.e.: challengePassword or unstructuredName).
		if err == nil && len(rest) == 0 {
			attributes = append(attributes, attr)
		}
	}
	return attributes
}

// parseCSRExtensions parses the attributes from a CSR and extracts any
// requested extensions.
func parseCSRExtensions(rawAttributes []asn1.RawValue) ([]pkix.Extension, error) {
	// pkcs10Attribute reflects the Attribute structure from section 4.1 of
	// https://tools.ietf.org/html/rfc2986.
	type pkcs10Attribute struct {
		Id     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}

	var ret []pkix.Extension
	for _, rawAttr := range rawAttributes {
		var attr pkcs10Attribute
		if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || len(rest) != 0 || len(attr.Values) == 0 {
			// Ignore attributes that don't parse.
			continue
		}

		if !attr.Id.Equal(oidExtensionRequest) {
			continue
		}

		var extensions []pkix.Extension
		if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil {
			return nil, err
		}
		ret = append(ret, extensions...)
	}

	return ret, nil
}

func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
func domainToReverseLabels(domain string) (reverseLabels []string, ok bool) {
	for len(domain) > 0 {
		if i := strings.LastIndexByte(domain, '.'); i == -1 {
			reverseLabels = append(reverseLabels, domain)
			domain = ""
		} else {
			reverseLabels = append(reverseLabels, domain[i+1:])
			domain = domain[:i]
		}
	}

	if len(reverseLabels) > 0 && len(reverseLabels[0]) == 0 {
		// An empty label at the end indicates an absolute value.
		return nil, false
	}

	for _, label := range reverseLabels {
		if len(label) == 0 {
			// Empty labels are otherwise invalid.
			return nil, false
		}

		for _, c := range label {
			if c < 33 || c > 126 {
				// Invalid character.
				return nil, false
			}
		}
	}

	return reverseLabels, true
}

func parseSANExtension(value []byte) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		switch tag {
		case nameTypeEmail:
			emailAddresses = append(emailAddresses, string(data))
		case nameTypeDNS:
			dnsNames = append(dnsNames, string(data))
		case nameTypeURI:
			uri, err := url.Parse(string(data))
			if err != nil {
				return fmt.Errorf("x509: cannot parse URI %q: %s", string(data), err)
			}
			if len(uri.Host) > 0 {
				if _, ok := domainToReverseLabels(uri.Host); !ok {
					return fmt.Errorf("x509: cannot parse URI %q: invalid domain", string(data))
				}
			}
			uris = append(uris, uri)
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))
			}
		}

		return nil
	})

	return
}

func VerifyDERCSRSign(asn1Data []byte, userId []byte) (bool, error) {
	csr, err := ParseCertificateRequest(asn1Data)
	if err != nil {
		return false, err
	}
	return VerifyCSRSign(csr, userId), nil
}

func VerifyCSRSign(csr *x509.CertificateRequest, userId []byte) bool {
	pub := csr.PublicKey.(*sm2.PublicKey)
	return sm2.Verify(pub, userId, csr.RawTBSCertificateRequest, csr.Signature)
}

func FillCertificateTemplateByCSR(template *x509.Certificate, csr *x509.CertificateRequest) {
	template.Subject = csr.Subject
	template.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	template.PublicKey = csr.PublicKey
	template.Extensions = csr.Extensions
	template.ExtraExtensions = csr.ExtraExtensions
	template.DNSNames = csr.DNSNames
	template.EmailAddresses = csr.EmailAddresses
	template.IPAddresses = csr.IPAddresses
	template.URIs = csr.URIs
}

func subjectBytes(cert *x509.Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

// RFC 5280, 4.2.1.12  Extended Key Usage
//
// anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
//
// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
//
// id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
// id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
// id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
// id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
// id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
// id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
var (
	oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
	oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
	oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
)

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage x509.ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{x509.ExtKeyUsageAny, oidExtKeyUsageAny},
	{x509.ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{x509.ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{x509.ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{x509.ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{x509.ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{x509.ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{x509.ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{x509.ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{x509.ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, oidExtKeyUsageMicrosoftCommercialCodeSigning},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, oidExtKeyUsageMicrosoftKernelCodeSigning},
}

func oidFromExtKeyUsage(eku x509.ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

func isIA5String(s string) error {
	for _, r := range s {
		if r >= utf8.RuneSelf {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func buildExtensions(template *x509.Certificate, subjectIsEmpty bool, authorityKeyId []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionKeyUsage
		ret[n].Critical = true

		var a [2]byte
		a[0] = reverseBitsInAByte(byte(template.KeyUsage))
		a[1] = reverseBitsInAByte(byte(template.KeyUsage >> 8))

		l := 1
		if a[1] != 0 {
			l = 2
		}

		bitString := a[:l]
		ret[n].Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionExtendedKeyUsage

		var oids []asn1.ObjectIdentifier
		for _, u := range template.ExtKeyUsage {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				panic("internal error")
			}
		}

		oids = append(oids, template.UnknownExtKeyUsage...)

		ret[n].Value, err = asn1.Marshal(oids)
		if err != nil {
			return
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		// Leaving MaxPathLen as zero indicates that no maximum path
		// length is desired, unless MaxPathLenZero is set. A value of
		// -1 causes encoding/asn1 to omit the value as desired.
		maxPathLen := template.MaxPathLen
		if maxPathLen == 0 && !template.MaxPathLenZero {
			maxPathLen = -1
		}
		ret[n].Id = oidExtensionBasicConstraints
		ret[n].Value, err = asn1.Marshal(basicConstraints{template.IsCA, maxPathLen})
		ret[n].Critical = true
		if err != nil {
			return
		}
		n++
	}

	if len(template.SubjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(template.SubjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(authorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{authorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCertificatePolicies
		policies := make([]policyInformation, len(template.PolicyIdentifiers))
		for i, policy := range template.PolicyIdentifiers {
			policies[i].Policy = policy
		}
		ret[n].Value, err = asn1.Marshal(policies)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		permitted, err := serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}

		excluded, err := serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function.

	return append(ret[:n], template.ExtraExtensions...), nil
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type TBSCertificate tbsCertificate

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// 为什么要将构建CertificateInfo和签发证书分开呢?
// 是因为实际应用中的CA密钥大多数都是放在加密卡/加密机中的，签名由加密卡/加密机来完成
func CreateCertificateInfo(template, parent *x509.Certificate, csr *x509.CertificateRequest) (*TBSCertificate, error) {
	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return nil, err
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return nil, err
	}

	authorityKeyId := template.AuthorityKeyId
	if !bytes.Equal(asn1Issuer, asn1Subject) && len(parent.SubjectKeyId) > 0 {
		authorityKeyId = parent.SubjectKeyId
	}

	extensions, err := buildExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), authorityKeyId)
	if err != nil {
		return nil, err
	}

	var sigAlgo pkix.AlgorithmIdentifier
	sigAlgo.Algorithm = oidSignatureSM3WithSM2
	var subjectPubKeyInfo publicKeyInfo
	rest, err := asn1.Unmarshal(csr.RawSubjectPublicKeyInfo, &subjectPubKeyInfo)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	c := TBSCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: sigAlgo,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          subjectPubKeyInfo,
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return nil, err
	}
	c.Raw = tbsCertContents
	return &c, nil
}

func IssueCertificateBySoftCAKey(cinfo *TBSCertificate, caPri *sm2.PrivateKey, userId []byte) ([]byte, error) {
	signature, err := sm2.Sign(caPri, userId, cinfo.Raw)
	if err != nil {
		return nil, err
	}
	return CreateCertificate(cinfo, signature)
}

func CreateCertificate(cinfo *TBSCertificate, signature []byte) ([]byte, error) {
	var sigAlgo pkix.AlgorithmIdentifier
	sigAlgo.Algorithm = oidSignatureSM3WithSM2
	return asn1.Marshal(certificate{
		nil,
		*cinfo,
		sigAlgo,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(asn1Data []byte) (*x509.Certificate, error) {
	var cert certificate
	rest, err := asn1.Unmarshal(asn1Data, &cert)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	return parseCertificate(&cert)
}

func parseCertificate(in *certificate) (*x509.Certificate, error) {
	out := new(x509.Certificate)
	out.Raw = in.Raw
	out.RawTBSCertificate = in.TBSCertificate.Raw
	out.RawSubjectPublicKeyInfo = in.TBSCertificate.PublicKey.Raw
	out.RawSubject = in.TBSCertificate.Subject.FullBytes
	out.RawIssuer = in.TBSCertificate.Issuer.FullBytes

	out.Signature = in.SignatureValue.RightAlign()
	out.SignatureAlgorithm = 0
	out.PublicKeyAlgorithm = 0

	if !oidSignatureSM3WithSM2.Equal(in.SignatureAlgorithm.Algorithm) {
		return nil, errors.New("x509: illegal signature algorithm OID")
	}
	if !oidPublicKeyECDSA.Equal(in.TBSCertificate.PublicKey.Algorithm.Algorithm) {
		return nil, errors.New("x509: illegal publick key algorithm OID")
	}

	var err error
	out.PublicKey, err = parsePublicKey(&in.TBSCertificate.PublicKey)
	if err != nil {
		return nil, err
	}

	out.Version = in.TBSCertificate.Version + 1
	out.SerialNumber = in.TBSCertificate.SerialNumber

	var issuer, subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(in.TBSCertificate.Subject.FullBytes, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 subject")
	}
	if rest, err := asn1.Unmarshal(in.TBSCertificate.Issuer.FullBytes, &issuer); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 subject")
	}

	out.Issuer.FillFromRDNSequence(&issuer)
	out.Subject.FillFromRDNSequence(&subject)

	out.NotBefore = in.TBSCertificate.Validity.NotBefore
	out.NotAfter = in.TBSCertificate.Validity.NotAfter

	for _, e := range in.TBSCertificate.Extensions {
		out.Extensions = append(out.Extensions, e)
		unhandled := false

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				// RFC 5280, 4.2.1.3
				var usageBits asn1.BitString
				if rest, err := asn1.Unmarshal(e.Value, &usageBits); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 KeyUsage")
				}

				var usage int
				for i := 0; i < 9; i++ {
					if usageBits.At(i) != 0 {
						usage |= 1 << uint(i)
					}
				}
				out.KeyUsage = x509.KeyUsage(usage)

			case 19:
				// RFC 5280, 4.2.1.9
				var constraints basicConstraints
				if rest, err := asn1.Unmarshal(e.Value, &constraints); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 BasicConstraints")
				}

				out.BasicConstraintsValid = true
				out.IsCA = constraints.IsCA
				out.MaxPathLen = constraints.MaxPathLen
				out.MaxPathLenZero = out.MaxPathLen == 0
				// TODO: map out.MaxPathLen to 0 if it has the -1 default value? (Issue 19285)
			case 17:
				out.DNSNames, out.EmailAddresses, out.IPAddresses, out.URIs, err = parseSANExtension(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.DNSNames) == 0 && len(out.EmailAddresses) == 0 && len(out.IPAddresses) == 0 && len(out.URIs) == 0 {
					// If we didn't parse anything then we do the critical check, below.
					unhandled = true
				}

			case 30:
				unhandled, err = parseNameConstraintsExtension(out, e)
				if err != nil {
					return nil, err
				}

			case 31:
				// RFC 5280, 4.2.1.13

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

				var cdp []distributionPoint
				if rest, err := asn1.Unmarshal(e.Value, &cdp); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 CRL distribution point")
				}

				for _, dp := range cdp {
					// Per RFC 5280, 4.2.1.13, one of distributionPoint or cRLIssuer may be empty.
					if len(dp.DistributionPoint.FullName) == 0 {
						continue
					}

					for _, fullName := range dp.DistributionPoint.FullName {
						if fullName.Tag == 6 {
							out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(fullName.Bytes))
						}
					}
				}

			case 35:
				// RFC 5280, 4.2.1.1
				var a authKeyId
				if rest, err := asn1.Unmarshal(e.Value, &a); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 authority key-id")
				}
				out.AuthorityKeyId = a.Id

			case 37:
				// RFC 5280, 4.2.1.12.  Extended Key Usage

				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER

				var keyUsage []asn1.ObjectIdentifier
				if rest, err := asn1.Unmarshal(e.Value, &keyUsage); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 ExtendedKeyUsage")
				}

				for _, u := range keyUsage {
					if extKeyUsage, ok := extKeyUsageFromOID(u); ok {
						out.ExtKeyUsage = append(out.ExtKeyUsage, extKeyUsage)
					} else {
						out.UnknownExtKeyUsage = append(out.UnknownExtKeyUsage, u)
					}
				}

			case 14:
				// RFC 5280, 4.2.1.2
				var keyid []byte
				if rest, err := asn1.Unmarshal(e.Value, &keyid); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 key-id")
				}
				out.SubjectKeyId = keyid

			case 32:
				// RFC 5280 4.2.1.4: Certificate Policies
				var policies []policyInformation
				if rest, err := asn1.Unmarshal(e.Value, &policies); err != nil {
					return nil, err
				} else if len(rest) != 0 {
					return nil, errors.New("x509: trailing data after X.509 certificate policies")
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, len(policies))
				for i, policy := range policies {
					out.PolicyIdentifiers[i] = policy.Policy
				}

			default:
				// Unknown extensions are recorded if critical.
				unhandled = true
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			var aia []authorityInfoAccess
			if rest, err := asn1.Unmarshal(e.Value, &aia); err != nil {
				return nil, err
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 authority information")
			}

			for _, v := range aia {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if v.Location.Tag != 6 {
					continue
				}
				if v.Method.Equal(oidAuthorityInfoAccessOcsp) {
					out.OCSPServer = append(out.OCSPServer, string(v.Location.Bytes))
				} else if v.Method.Equal(oidAuthorityInfoAccessIssuers) {
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(v.Location.Bytes))
				}
			}
		} else {
			// Unknown extensions are recorded if critical.
			unhandled = true
		}

		if e.Critical && unhandled {
			out.UnhandledCriticalExtensions = append(out.UnhandledCriticalExtensions, e.Id)
		}
	}

	return out, nil
}

func parseNameConstraintsExtension(out *x509.Certificate, e pkix.Extension) (unhandled bool, err error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := cryptobyte.String(e.Value)
	var toplevel, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
				emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
				ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
				uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain
					// itself, but that's not valid in a
					// normal domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				} else {
					// Otherwise it's a domain name.
					domain := constraint
					if len(domain) > 0 && domain[0] == '.' {
						domain = domain[1:]
					}
					if _, ok := domainToReverseLabels(domain); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain itself,
					// but that's not valid in a normal
					// domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}

// isValidIPMask returns true iff mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

// rfc2821Mailbox represents a “mailbox” (which is an email address to most
// people) by breaking it into the “local” (i.e. before the '@') and “domain”
// parts.
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a “Mailbox” from RFC 2821. According to
// https://tools.ietf.org/html/rfc5280#section-4.2.1.6 that's correct for an
// rfc822Name from a certificate: “The format of an rfc822Name is a "Mailbox"
// as defined in https://tools.ietf.org/html/rfc2821#section-4.1.2”.
func parseRFC2821Mailbox(in string) (mailbox rfc2821Mailbox, ok bool) {
	if len(in) == 0 {
		return mailbox, false
	}

	localPartBytes := make([]byte, 0, len(in)/2)

	if in[0] == '"' {
		// Quoted-string = DQUOTE *qcontent DQUOTE
		// non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
		// qcontent = qtext / quoted-pair
		// qtext = non-whitespace-control /
		//         %d33 / %d35-91 / %d93-126
		// quoted-pair = ("\" text) / obs-qp
		// text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
		//
		// (Names beginning with “obs-” are the obsolete syntax from
		// https://tools.ietf.org/html/rfc2822#section-4. Since it has
		// been 16 years, we no longer accept that.)
		in = in[1:]
	QuotedString:
		for {
			if len(in) == 0 {
				return mailbox, false
			}
			c := in[0]
			in = in[1:]

			switch {
			case c == '"':
				break QuotedString

			case c == '\\':
				// quoted-pair
				if len(in) == 0 {
					return mailbox, false
				}
				if in[0] == 11 ||
					in[0] == 12 ||
					(1 <= in[0] && in[0] <= 9) ||
					(14 <= in[0] && in[0] <= 127) {
					localPartBytes = append(localPartBytes, in[0])
					in = in[1:]
				} else {
					return mailbox, false
				}

			case c == 11 ||
				c == 12 ||
				// Space (char 32) is not allowed based on the
				// BNF, but RFC 3696 gives an example that
				// assumes that it is. Several “verified”
				// errata continue to argue about this point.
				// We choose to accept it.
				c == 32 ||
				c == 33 ||
				c == 127 ||
				(1 <= c && c <= 8) ||
				(14 <= c && c <= 31) ||
				(35 <= c && c <= 91) ||
				(93 <= c && c <= 126):
				// qtext
				localPartBytes = append(localPartBytes, c)

			default:
				return mailbox, false
			}
		}
	} else {
		// Atom ("." Atom)*
	NextChar:
		for len(in) > 0 {
			// atext from https://tools.ietf.org/html/rfc2822#section-3.2.4
			c := in[0]

			switch {
			case c == '\\':
				// Examples given in RFC 3696 suggest that
				// escaped characters can appear outside of a
				// quoted string. Several “verified” errata
				// continue to argue the point. We choose to
				// accept it.
				in = in[1:]
				if len(in) == 0 {
					return mailbox, false
				}
				fallthrough

			case ('0' <= c && c <= '9') ||
				('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				c == '!' || c == '#' || c == '$' || c == '%' ||
				c == '&' || c == '\'' || c == '*' || c == '+' ||
				c == '-' || c == '/' || c == '=' || c == '?' ||
				c == '^' || c == '_' || c == '`' || c == '{' ||
				c == '|' || c == '}' || c == '~' || c == '.':
				localPartBytes = append(localPartBytes, in[0])
				in = in[1:]

			default:
				break NextChar
			}
		}

		if len(localPartBytes) == 0 {
			return mailbox, false
		}

		// https://tools.ietf.org/html/rfc3696#section-3
		// “period (".") may also appear, but may not be used to start
		// or end the local part, nor may two or more consecutive
		// periods appear.”
		twoDots := []byte{'.', '.'}
		if localPartBytes[0] == '.' ||
			localPartBytes[len(localPartBytes)-1] == '.' ||
			bytes.Contains(localPartBytes, twoDots) {
			return mailbox, false
		}
	}

	if len(in) == 0 || in[0] != '@' {
		return mailbox, false
	}
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}

	mailbox.local = string(localPartBytes)
	mailbox.domain = in
	return mailbox, true
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku x509.ExtKeyUsage, ok bool) {
	for _, pair := range extKeyUsageOIDs {
		if oid.Equal(pair.oid) {
			return pair.extKeyUsage, true
		}
	}
	return
}
