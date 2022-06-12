package server

import (
	"context"
	"crypto/tls"
	"strings"
	_ "unsafe"

	"github.com/jxskiss/gopkg/v2/forceexport"
	"github.com/jxskiss/gopkg/v2/reflectx"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func init() {
	_certKey_typ := reflectx.RTypeOf(_certKey{})
	autocert_certKey_typ := forceexport.GetType("golang.org/x/crypto/acme/autocert.certKey")
	isSameField := func(i int) bool {
		f1 := _certKey_typ.Field(i)
		f2 := autocert_certKey_typ.Field(i)
		return f1.Name == f2.Name && f1.Type == f2.Type && f1.Offset == f2.Offset
	}
	for i := 0; i < _certKey_typ.NumField(); i++ {
		if !isSameField(i) {
			panic("autocert.certKey has been changed, unsafe tricks won't work")
		}
	}
}

// _certKey is copied from autocert.certKey.
type _certKey struct {
	domain  string // without trailing dot
	isRSA   bool   // RSA cert for legacy clients (as opposed to default ECDSA)
	isToken bool   // tls-based challenge token cert; key type is undefined regardless of isRSA
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
