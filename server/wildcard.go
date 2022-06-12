package server

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"

	"github.com/jxskiss/ssl-cert-server/pkg/lego"
)

var wildcardDomainCheckResultCache sync.Map

func IsWildcardDomain(domain string) (item *wildcardItem, ok bool) {
	type checkResult struct {
		item *wildcardItem
		ok   bool
	}
	if val, ok := wildcardDomainCheckResultCache.Load(domain); ok {
		result := val.(*checkResult)
		return result.item, result.ok
	}

	cfg := Cfg
	item = cfg.CheckWildcardDomain(domain)
	if item != nil {
		ok = true
	}
	wildcardDomainCheckResultCache.Store(domain, &checkResult{item, ok})
	return item, ok
}

func NewWildcardManager(ocspMgr *OCSPManager) *WildcardManager {
	return &WildcardManager{
		ocspMgr: ocspMgr,
		log:     zlog.Named("wildcard").Sugar(),
	}
}

func (p *wildcardItem) CacheKey() string {
	return fmt.Sprintf("wildcard_%s", p.RootDomain)
}

func (p *wildcardItem) OCSPKeyName() string {
	return fmt.Sprintf("wildcard|%s", p.RootDomain)
}

type wildcardCert struct {
	sync.Mutex
	item *wildcardItem
	cert unsafe.Pointer // *withPEMCert

	renewing uint32
}

func (p *wildcardCert) saveCertificate(tlscert *tls.Certificate, privPEM, pubPEM []byte, saveToStorage bool) error {
	atomic.StorePointer(&p.cert, unsafe.Pointer(&withPEMCert{
		tlscert: tlscert,
		privPEM: privPEM,
		pubPEM:  pubPEM,
	}))
	if saveToStorage {
		certKey := p.item.CacheKey()
		err := saveCertificateToStore(certKey, privPEM, pubPEM)
		if err != nil {
			return err
		}
	}
	return nil
}

type withPEMCert struct {
	tlscert *tls.Certificate
	privPEM []byte
	pubPEM  []byte
}

type WildcardManager struct {
	cache   sync.Map
	ocspMgr *OCSPManager
	log     *zap.SugaredLogger

	renewalOnce sync.Once
}

func (p *WildcardManager) Get(item *wildcardItem, issueIfNotCached bool) (*tls.Certificate, error) {
	tlscert, err := p.getWildcardCertificate(item, issueIfNotCached)
	if err != nil {
		return nil, err
	}

	ocspKeyName := item.OCSPKeyName()
	p.ocspMgr.Watch(ocspKeyName, func() (*tls.Certificate, error) {
		return p.getWildcardCertificate(item, false)
	})

	return tlscert, nil
}

func (p *WildcardManager) getWildcardCertificate(item *wildcardItem, issueIfNotCached bool) (*tls.Certificate, error) {
	certKey := item.CacheKey()
	cached, ok := p.cache.Load(certKey)
	if ok {
		wcCert := cached.(*wildcardCert)
		pemCert := (*withPEMCert)(atomic.LoadPointer(&wcCert.cert))
		if pemCert != nil {
			return pemCert.tlscert, nil
		}
	}

	// Certificate is not cached, check storage.
	cached, _ = p.cache.LoadOrStore(certKey, &wildcardCert{
		item: item,
	})
	wcCert := cached.(*wildcardCert)
	wcCert.Lock()
	defer wcCert.Unlock()

	pemCert := (*withPEMCert)(atomic.LoadPointer(&wcCert.cert))
	if pemCert != nil {
		return pemCert.tlscert, nil
	}

	tlscert, privPEM, pubPEM, err := loadCertificateFromStore(certKey)
	if err != nil && err != ErrCacheMiss {
		return nil, fmt.Errorf("wildcard: failed load certificate: %w", err)
	}
	if tlscert != nil && time.Until(tlscert.Leaf.NotAfter) > time.Hour {
		p.log.Infof("load certificate from storage: rootDomain= %v notAfter= %v", item.RootDomain, tlscert.Leaf.NotAfter)
		err = wcCert.saveCertificate(tlscert, privPEM, pubPEM, false)
		if err != nil {
			return nil, fmt.Errorf("wildcard: failed save certificate")
		}
		p.renewalOnce.Do(p.startRenewal)
		return tlscert, nil
	}
	if !issueIfNotCached {
		return nil, ErrCacheMiss
	}

	// Certificate is not available from cache, issue a new certificate.
	p.log.Infof("issuing new certifidcate: rootDomain= %v", item.RootDomain)
	certArgs := newLegoCertArgs(item)
	legoCert, err := lego.IssueCertificate(certArgs)
	if err != nil {
		return nil, fmt.Errorf("wildcard: failed issue certificate: %w", err)
	}

	p.log.Infof("issued certificate: rootDomain= %v", item.RootDomain)
	err = wcCert.saveCertificate(legoCert.Certificate, legoCert.KeyPEM, legoCert.CertPEM, true)
	if err != nil {
		return nil, fmt.Errorf("wildcard: failed save certificate: %w", err)
	}

	p.renewalOnce.Do(p.startRenewal)
	return legoCert.Certificate, nil
}

func newLegoCertArgs(wcItem *wildcardItem) *lego.CertArgs {
	cfg := Cfg
	cred := cfg.Wildcard.credentialMap[wcItem.Credential]
	return &lego.CertArgs{
		DataPath:   cfg.Wildcard.LegoDataPath,
		Email:      cfg.LetsEncrypt.Email,
		Server:     cfg.LetsEncrypt.DirectoryURL,
		DnsCode:    cred.Provider,
		Env:        cred.Env,
		RootDomain: wcItem.RootDomain,
		Domains:    wcItem.Domains,
		Hook:       "",
	}
}

func (p *WildcardManager) startRenewal() {
	tickInterval := 10 * time.Minute
	go func() {
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()
		for range ticker.C {
			p.doRenew()
		}
	}()
}

func (p *WildcardManager) doRenew() {

	cfg := Cfg
	renewDur := 24 * time.Hour * time.Duration(cfg.LetsEncrypt.RenewBefore)

	var wg sync.WaitGroup
	var token = make(chan struct{}, 10)
	p.cache.Range(func(key, value any) bool {
		wcCert := value.(*wildcardCert)
		pemCert := (*withPEMCert)(atomic.LoadPointer(&wcCert.cert))
		if pemCert == nil {
			p.log.Infof("certificate is not ready to renew: rootDomain= %s", wcCert.item.RootDomain)
			return true
		}
		if time.Until(pemCert.tlscert.Leaf.NotAfter) > renewDur {
			return true
		}
		if !atomic.CompareAndSwapUint32(&wcCert.renewing, 0, 1) {
			return true
		}

		wg.Add(1)
		token <- struct{}{}
		go func() {
			defer func() {
				wg.Done()
				<-token
				atomic.StoreUint32(&wcCert.renewing, 0)
			}()
			p.renewCertificate(wcCert)
		}()
		return true
	})
	wg.Wait()
}

func (p *WildcardManager) renewCertificate(wcCert *wildcardCert) {
	cfg := Cfg

	certArgs := newLegoCertArgs(wcCert.item)
	certArgs.RenewOpts.Days = cfg.LetsEncrypt.RenewBefore
	certArgs.RenewOpts.ReuseKey = true

	pemCert := (*withPEMCert)(atomic.LoadPointer(&wcCert.cert))
	oldCert := &lego.Certificate{
		RootDomain:  wcCert.item.RootDomain,
		Domains:     wcCert.item.Domains,
		CertPEM:     pemCert.pubPEM,
		KeyPEM:      pemCert.privPEM,
		Certificate: pemCert.tlscert,
	}

	p.log.Infof("renewing certificate: rootDomain= %v", wcCert.item.RootDomain)
	newCert, err := lego.RenewCertificate(certArgs, oldCert)
	if err != nil {
		p.log.Errorf("failed renew certificate: rootDomain= %v err= %v", wcCert.item.RootDomain, err)
		return
	}
	if newCert.Certificate.Leaf.NotAfter.Sub(oldCert.Certificate.Leaf.NotAfter) > 0 {
		p.log.Infof("renewed certificate: rootDomain= %v notAfter= %v",
			wcCert.item.RootDomain, newCert.Certificate.Leaf.NotAfter)
		err = wcCert.saveCertificate(newCert.Certificate, newCert.KeyPEM, newCert.CertPEM, true)
		if err != nil {
			p.log.Errorf("failed save certificate: rootDomain= %v err= %v", wcCert.item.RootDomain, err)
		}
	}
}
