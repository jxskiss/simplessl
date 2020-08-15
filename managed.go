package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const reloadInterval = 300 // seconds

var managedCache sync.Map

type managedCert struct {
	sync.Mutex
	cert   unsafe.Pointer // *tls.Certificate
	loadAt int64
}

func IsManagedDomain(domain string) (cert, privKey string, ok bool) {
	for _, x := range Cfg.Managed {
		if x.Regex.MatchString(domain) {
			return x.Cert, x.PrivKey, true
		}
	}
	return "", "", false
}

func GetManagedCertificate(cert, privKey string) (*tls.Certificate, error) {
	tlscert, err := getManagedCertificate(cert, privKey)
	if err != nil {
		return nil, err
	}

	ocspKeyName := managedCertOCSPKeyName(cert, privKey)
	OCSPManager.Watch(ocspKeyName, func() (*tls.Certificate, error) {
		return getManagedCertificate(cert, privKey)
	})

	return tlscert, nil
}

func getManagedCertificate(cert, privKey string) (*tls.Certificate, error) {
	ckey := cert + "_" + privKey
	cached, ok := managedCache.Load(ckey)
	if ok {
		mngCert := cached.(*managedCert)
		tlscert := atomic.LoadPointer(&mngCert.cert)
		if tlscert != nil {
			if mngCert.loadAt > 0 &&
				time.Now().Unix()-mngCert.loadAt > reloadInterval {
				go reloadManagedCertificate(mngCert, cert, privKey)
			}
			return (*tls.Certificate)(tlscert), nil
		}
	}

	// certificate not cached, lock and load from storage
	cached, _ = managedCache.LoadOrStore(ckey, &managedCert{})
	mngCert := cached.(*managedCert)
	mngCert.Lock()
	defer mngCert.Unlock()

	if mngCert.cert != nil {
		return (*tls.Certificate)(mngCert.cert), nil
	}
	tlscert, err := loadManagedCertificateFromStore(cert, privKey)
	if err != nil {
		return nil, err
	}
	atomic.StorePointer(&mngCert.cert, unsafe.Pointer(tlscert))
	mngCert.loadAt = time.Now().Unix()
	return tlscert, nil
}

func loadManagedCertificateFromStore(cert, privKey string) (*tls.Certificate, error) {
	store := Cfg.Storage.Cache
	ctx := context.Background()
	certPEM, err := store.Get(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("managed: failed get certificate from %s: %v", cert, err)
	}
	privKeyPEM, err := store.Get(ctx, privKey)
	if err != nil {
		return nil, fmt.Errorf("managed: failed get private key from %s: %v", privKey, err)
	}
	tlscert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("managed: failed parse public/private key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("managed: failed parse x509 certificate: %v", err)
	}
	tlscert.Leaf = leaf
	return &tlscert, nil
}

func reloadManagedCertificate(mngCert *managedCert, cert, privKey string) {
	tlscert, err := loadManagedCertificateFromStore(cert, privKey)
	if err != nil {
		log.Printf("[WARN] managed: failed reload certificate: cert= %s priv_key= %s", cert, privKey)
		return
	}
	mngCert.Lock()
	defer mngCert.Unlock()
	atomic.StorePointer(&mngCert.cert, unsafe.Pointer(tlscert))
	mngCert.loadAt = time.Now().Unix()
}

func managedCertOCSPKeyName(cert, privKey string) string {
	return fmt.Sprintf("managed|%s|%s", cert, privKey)
}
