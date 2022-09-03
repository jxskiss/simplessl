package proto

import "crypto/tls"

// V1 certificate types.
//
// - smaller than 100 for certificates which have OCSP stapling;
// - equal or larger than 100 for certificates which don't have OCSP stapling;
const (
	V1TypeLetsEncrypt = 0
	V1TypeManaged     = 1
	V1TypeWildcard    = 2
	V1TypeSelfSigned  = 100
	V1TypeALPNCert    = 101
)

func ToV2CertificateType(v1Typ int) Certificate_Type {
	switch v1Typ {
	case V1TypeLetsEncrypt:
		return Certificate_ACME_ON_DEMAND
	case V1TypeManaged:
		return Certificate_MANAGED
	case V1TypeWildcard:
		return Certificate_ACME_NAMED
	case V1TypeSelfSigned:
		return Certificate_SELF_SIGNED
	case V1TypeALPNCert:
		return Certificate_ALPN
	}
	return Certificate_UNKNOWN
}

func V1HasOCSPStapling(certType int, cert *tls.Certificate) bool {
	return certType < 100 &&
		cert.Leaf != nil && len(cert.Leaf.OCSPServer) > 0
}
