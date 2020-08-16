package server

import (
	"crypto/tls"
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

func IsManagedDomain(domain string) (certKey string, ok bool) {
	for _, x := range Cfg.Managed {
		if x.Regex.MatchString(domain) {
			return x.CertKey, true
		}
	}
	return "", false
}

func GetManagedCertificate(certKey string) (*tls.Certificate, error) {
	tlscert, err := getManagedCertificate(certKey)
	if err != nil {
		return nil, err
	}

	ocspKeyName := managedCertOCSPKeyName(certKey)
	OCSPManager.Watch(ocspKeyName, func() (*tls.Certificate, error) {
		return getManagedCertificate(certKey)
	})

	return tlscert, nil
}

func getManagedCertificate(certKey string) (*tls.Certificate, error) {
	cached, ok := managedCache.Load(certKey)
	if ok {
		mngCert := cached.(*managedCert)
		tlscert := atomic.LoadPointer(&mngCert.cert)
		if tlscert != nil {
			if mngCert.loadAt > 0 &&
				time.Now().Unix()-mngCert.loadAt > reloadInterval {
				go reloadManagedCertificate(mngCert, certKey)
			}
			return (*tls.Certificate)(tlscert), nil
		}
	}

	// certificate not cached, lock and load from storage
	cached, _ = managedCache.LoadOrStore(certKey, &managedCert{})
	mngCert := cached.(*managedCert)
	mngCert.Lock()
	defer mngCert.Unlock()

	if mngCert.cert != nil {
		return (*tls.Certificate)(mngCert.cert), nil
	}
	tlscert, err := loadCertificateFromStore(certKey)
	if err != nil {
		return nil, fmt.Errorf("managed: %v", err)
	}
	atomic.StorePointer(&mngCert.cert, unsafe.Pointer(tlscert))
	mngCert.loadAt = time.Now().Unix()
	return tlscert, nil
}

func reloadManagedCertificate(mngCert *managedCert, certKey string) {
	tlscert, err := loadCertificateFromStore(certKey)
	if err != nil {
		log.Printf("[WARN] managed: failed reload certificate: cert_key= %s err= %v", certKey, err)
		return
	}
	mngCert.Lock()
	defer mngCert.Unlock()
	atomic.StorePointer(&mngCert.cert, unsafe.Pointer(tlscert))
	mngCert.loadAt = time.Now().Unix()
}

func managedCertOCSPKeyName(certKey string) string {
	return fmt.Sprintf("managed|%s", certKey)
}
