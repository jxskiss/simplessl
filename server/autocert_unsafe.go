package server

import (
	"context"
	"crypto/tls"
	"strings"
	_ "unsafe"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// _certKey is copied from autocert.certKey.
type _certKey struct {
	domain  string // without trailing dot
	isRSA   bool   // RSA cert for legacy clients (as opposed to default ECDSA)
	isToken bool   // tls-based challenge token cert; key type is undefined regardless of isRSA
}

func init() {
	// TODO: assert _certkey equality
}

//go:linkname _autocert_Manager_cert golang.org/x/crypto/acme/autocert.(*Manager).cert
func _autocert_Manager_cert(mgr *autocert.Manager, ctx context.Context, ck _certKey) (*tls.Certificate, error)

//go:linkname _autocert_Manager_acmeClient golang.org/x/crypto/acme/autocert.(*Manager).acmeClient
func _autocert_Manager_acmeClient(mgr *autocert.Manager, ctx context.Context) (*acme.Client, error)

//go:linkname _autocert_supportsECDSA golang.org/x/crypto/acme/autocert.supportsECDSA
func _autocert_supportsECDSA(hello *tls.ClientHelloInfo) bool

func (m *Manager) getCachedCertificateForOCSPStapling(name string) (
	cert *tls.Certificate,
	err error,
) {
	if ck, ok := IsManagedDomain(name); ok {
		return m.managed.Get(ck)
	}
	if wcItem, ok := IsWildcardDomain(name); ok {
		return m.wildcard.Get(wcItem, false)
	}

	// Else check cached certificates from Let's Encrypt, but don't trigger
	// requests to issue new certificates.
	err = m.autocert.HostPolicy(context.Background(), name)
	if err != nil {
		return nil, err
	}
	ck := _certKey{
		domain: strings.TrimSuffix(name, "."), // golang.org/issue/18114
		isRSA:  !_autocert_supportsECDSA(m.helloInfo(name)),
	}
	cert, err = _autocert_Manager_cert(m.autocert, context.Background(), ck)
	if err != nil {
		return nil, err
	}
	m.watchCert(name)
	return cert, nil
}
