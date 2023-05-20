package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/jxskiss/simplessl/pkg/bus"
	"github.com/jxskiss/simplessl/pkg/config"
	"github.com/jxskiss/simplessl/pkg/pb"
	"github.com/jxskiss/simplessl/pkg/utils"
)

const acmeCheckRenewInterval = 10 * time.Minute

type ACMEManager interface {
	GetNamedCertificate(ctx context.Context, name string, createIfNotCached bool) (*tls.Certificate, error)
	GetOnDemandCertificate(ctx context.Context, domain string, createIfNotCached bool) (*tls.Certificate, error)
}

func NewACMEManager(
	cfg *config.Config,
	bus bus.EventBus,
	storMgr StorageManager,
	ocsp OCSPManager,
	httpSolver HTTPAndTLSALPNSolver,
) ACMEManager {
	impl := &acmeImpl{
		cfg:        cfg,
		bus:        bus,
		storMgr:    storMgr,
		ocsp:       ocsp,
		httpSolver: httpSolver,
		log:        zlog.Named("acmeManager").Sugar(),
	}
	impl.startRenewal()
	return impl
}

type acmeImpl struct {
	cfg     *config.Config
	bus     bus.EventBus
	storMgr StorageManager
	ocsp    OCSPManager

	onDemandMu    sync.Mutex
	onDemandCache sync.Map

	namedMu    sync.Mutex
	namedCache sync.Map

	httpSolver HTTPAndTLSALPNSolver

	log *zap.SugaredLogger
}

func (p *acmeImpl) GetNamedCertificate(ctx context.Context, name string, createIfNotCached bool) (*tls.Certificate, error) {
	cert, err := p._getNamedCertificate(ctx, name, createIfNotCached)
	if err != nil {
		return nil, err
	}

	certKey := getCertKey(pb.Certificate_ACME_NAMED, name)
	p.ocsp.Watch(ctx, certKey, func() (*tls.Certificate, error) {
		// When watching from certificate manager,
		// there is no need to trigger watching again,
		// use the internal method here.
		return p._getNamedCertificate(ctx, name, false)
	})

	return cert, nil
}

func (p *acmeImpl) _getNamedCertificate(ctx context.Context, name string, createIfNotCached bool) (*tls.Certificate, error) {
	cached, ok := p.namedCache.Load(name)
	if !ok {
		cached, _ = p.namedCache.LoadOrStore(name, &acmeCert{
			mgr:  p,
			typ:  pb.Certificate_ACME_NAMED,
			name: name,
		})
	}
	return p.loadNamedCertificateFromStorageOrCreate(ctx, cached.(*acmeCert), createIfNotCached)
}

func (p *acmeImpl) loadNamedCertificateFromStorageOrCreate(ctx context.Context, acmeCert *acmeCert, createIfNotCached bool) (*tls.Certificate, error) {
	acmeCert.Lock()
	defer acmeCert.Unlock()

	if cert := acmeCert.cert.Load(); cert != nil {
		return (*tls.Certificate)(cert), nil
	}

	cert, err := acmeCert.loadFromStorage(ctx)
	if err != nil {
		if err != ErrCacheMiss {
			return nil, err
		}

		// ErrCacheMiss
		if !createIfNotCached {
			return nil, err
		}
	}

	// We got the cached certificate.
	if cert != nil {
		p.log.Infof("load named certificate from storage, name= %v, notAfter= %v",
			acmeCert.name, cert.Leaf.NotAfter)
		acmeCert.cert.Store(unsafe.Pointer(cert))
		return cert, nil
	}

	// Issue a new certificate and save to storage.
	p.log.Infof("obtaining new named certificate, name= %v", acmeCert.name)
	cfgCert := p.cfg.GetNamedACMECertificate(acmeCert.name)
	if cfgCert == nil {
		return nil, fmt.Errorf("certificate not configured: %v", acmeCert.name)
	}
	domains := cfgCert.Domains
	acmeRespCert, err := p.issueCertificate(ctx, acmeCert.name, domains)
	if err != nil {
		return nil, err
	}

	p.log.Infof("saving new named certificate, name= %v", acmeCert.name)
	cert, err = p.saveACMECertificate(ctx, acmeCert, acmeRespCert)
	if err != nil {
		return nil, err
	}

	acmeCert.cert.Store(unsafe.Pointer(cert))
	return cert, nil
}

func (p *acmeImpl) GetOnDemandCertificate(ctx context.Context, domain string, createIfNotCached bool) (*tls.Certificate, error) {
	cert, err := p._getOnDemandCertificate(ctx, domain, createIfNotCached)
	if err != nil {
		return nil, err
	}

	certKey := getCertKey(pb.Certificate_ACME_ON_DEMAND, domain)
	p.ocsp.Watch(ctx, certKey, func() (*tls.Certificate, error) {
		// When watching from certificate manager,
		// there is no need to trigger watching again,
		// use the internal method here.
		return p._getOnDemandCertificate(ctx, domain, false)
	})

	return cert, nil
}

func (p *acmeImpl) _getOnDemandCertificate(ctx context.Context, domain string, createIfNotCached bool) (*tls.Certificate, error) {
	cached, ok := p.onDemandCache.Load(domain)
	if !ok {
		cached, _ = p.onDemandCache.LoadOrStore(domain, &acmeCert{
			mgr:  p,
			typ:  pb.Certificate_ACME_ON_DEMAND,
			name: domain,
		})
	}
	return p.loadOnDemandCertificateFromStorageOrCreate(ctx, cached.(*acmeCert), createIfNotCached)
}

func (p *acmeImpl) loadOnDemandCertificateFromStorageOrCreate(ctx context.Context, acmeCert *acmeCert, createIfNotCached bool) (*tls.Certificate, error) {
	acmeCert.Lock()
	defer acmeCert.Unlock()

	if cert := acmeCert.cert.Load(); cert != nil {
		return (*tls.Certificate)(cert), nil
	}

	cert, err := acmeCert.loadFromStorage(ctx)
	if err != nil {
		if err != ErrCacheMiss {
			return nil, err
		}

		// ErrCacheMiss
		if !createIfNotCached {
			return nil, err
		}
	}

	// We got the cached certificate.
	if cert != nil {
		p.log.Infof("load on-demand certificate from storage, domain= %v, notAfter= %v",
			acmeCert.name, cert.Leaf.NotAfter)
		acmeCert.cert.Store(unsafe.Pointer(cert))
		return cert, nil
	}

	// Issue a new certificate and save to storage.
	p.log.Infof("obtaining new on-demand certificate, domain= %v", acmeCert.name)
	domains := []string{acmeCert.name}
	acmeRespCert, err := p.issueCertificate(ctx, "", domains)
	if err != nil {
		return nil, err
	}

	p.log.Infof("saving new on-demand certificate, domain= %v", acmeCert.name)
	cert, err = p.saveACMECertificate(ctx, acmeCert, acmeRespCert)
	if err != nil {
		return nil, err
	}

	acmeCert.cert.Store(unsafe.Pointer(cert))
	return cert, nil
}

func (p *acmeImpl) saveACMECertificate(ctx context.Context, acmeCert *acmeCert, acmeRespCert *acmeRespCertificate) (*tls.Certificate, error) {
	privKey := acmeRespCert.PrivateKey
	pubKey := acmeRespCert.Certificate

	certBuf := append(slices.Clip(privKey), pubKey...)
	cert, privPEM, pubPEM, err := utils.ParseCertificate(certBuf)
	if err != nil {
		return nil, err
	}
	cacheKey := acmeCert.name
	err = p.storMgr.SaveCertificate(ctx, acmeCert.typ, cacheKey, pubPEM, privPEM)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (p *acmeImpl) getAccountPrivateKey(ctx context.Context, acc *config.ACMEAccount) (privKey *ecdsa.PrivateKey, err error) {
	keyBuf, err := p.storMgr.GetAccountPrivateKey(ctx, acc.Email)
	if err != nil && err != ErrCacheMiss {
		return nil, err
	}

	// Got existing private key.
	if len(keyBuf) > 0 {
		block, _ := pem.Decode(keyBuf)
		if err != nil {
			return nil, err
		}
		if block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("unexpected private key type: %v", block.Type)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	// Create a new private key and save to storage.
	var pkeyBuf bytes.Buffer
	privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	err = utils.EncodeECDSAKey(&pkeyBuf, privKey)
	if err != nil {
		return nil, err
	}
	err = p.storMgr.SaveAccountPrivateKey(ctx, acc.Email, pkeyBuf.Bytes())
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

type acmeCert struct {
	mgr  *acmeImpl
	typ  pb.Certificate_Type
	name string

	sync.Mutex
	cert atomic.UnsafePointer // *tls.Certificate

	renewing atomic.Bool
}

// loadFromStorage checks storage for cached certificate,
// the caller MUST hold the lock to prevent duplicate calling.
func (p *acmeCert) loadFromStorage(ctx context.Context) (*tls.Certificate, error) {
	cert := p.cert.Load()
	if cert != nil {
		return (*tls.Certificate)(cert), nil
	}

	cacheKey := p.name
	tlscert, _, _, err := p.mgr.storMgr.LoadCertificate(ctx, p.typ, cacheKey)
	if err != nil {
		return nil, err
	}
	return tlscert, nil
}

// -------- renewal -------- //

func (p *acmeImpl) startRenewal() {
	go func() {
		ticker := time.NewTicker(acmeCheckRenewInterval)
		defer ticker.Stop()
		for range ticker.C {
			p.doRenew()
		}
	}()
}

func (p *acmeImpl) doRenew() {
	cfg := p.cfg
	renewDur := 24 * time.Hour * time.Duration(cfg.ACME.RenewBefore)

	var wg sync.WaitGroup
	var token = make(chan struct{}, 10)

	var successCnt atomic.Int32
	var failedCnt atomic.Int32

	var checkAndDoRenew = func(acmeCert *acmeCert) bool {
		cert := (*tls.Certificate)(acmeCert.cert.Load())
		if cert == nil {
			p.log.Infof("certificate is not ready to renew: type= %v, name= %v",
				acmeCert.typ, acmeCert.name)
			return true
		}
		if time.Until(cert.Leaf.NotAfter) > renewDur {
			p.log.Debugf("certificate does not need to renew: type= %v, name= %v",
				acmeCert.typ, acmeCert.name)
			return true
		}
		if !acmeCert.renewing.CompareAndSwap(false, true) {
			return true
		}

		wg.Add(1)
		token <- struct{}{}
		go func() {
			defer func() {
				wg.Done()
				<-token
				acmeCert.renewing.Store(false)
			}()
			success := p.renewCertificate(acmeCert)
			if success {
				successCnt.Inc()
			} else {
				failedCnt.Inc()
			}
		}()
		return true
	}

	p.namedCache.Range(func(key, value any) bool {
		acmeCert := value.(*acmeCert)
		return checkAndDoRenew(acmeCert)
	})

	p.onDemandCache.Range(func(key, value any) bool {
		acmeCert := value.(*acmeCert)
		return checkAndDoRenew(acmeCert)
	})

	wg.Wait()
	p.log.Infof("success check and do certificate renewal, success= %v, failed= %v",
		successCnt.Load(), failedCnt.Load())
}

func (p *acmeImpl) renewCertificate(acmeCert *acmeCert) (success bool) {
	p.log.Infof("renewing certificate: type= %v, name= %v", acmeCert.typ, acmeCert.name)

	ctx := context.Background()

	var certTyp = acmeCert.typ
	var certName string
	var domains []string
	switch certTyp {
	case pb.Certificate_ACME_ON_DEMAND:
		certName = ""
		domains = []string{acmeCert.name}
	case pb.Certificate_ACME_NAMED:
		cfgCert := p.cfg.GetNamedACMECertificate(acmeCert.name)
		if cfgCert == nil {
			p.log.Warnf("certificate not configured: %v", acmeCert.name)
			return false
		}
		certName = acmeCert.name
		domains = cfgCert.Domains
	}

	acmeRespCert, err := p.issueCertificate(ctx, certName, domains)
	if err != nil {
		p.log.Errorf("failed renew certificate, certName= %v, domains= %v, err= %v",
			certName, domains, err)
		return false
	}
	cert, err := p.saveACMECertificate(ctx, acmeCert, acmeRespCert)
	if err != nil {
		p.log.Errorf("failed save new certificate, certName= %v, domains= %v, err= %v",
			certName, domains, err)
		return false
	}
	acmeCert.cert.Store(unsafe.Pointer(cert))

	// notify OCSP stapling manager
	acmeCertName := acmeCert.name
	certKey := getCertKey(certTyp, acmeCertName)
	p.ocsp.NotifyCertChange(certKey, func() (*tls.Certificate, error) {
		ctx := context.Background()
		switch certTyp {
		case pb.Certificate_ACME_ON_DEMAND:
			return p._getOnDemandCertificate(ctx, acmeCertName, false)
		case pb.Certificate_ACME_NAMED:
			return p._getNamedCertificate(ctx, acmeCertName, false)
		}
		panic("bug: unexpected certificate type")
	})
	p.publishRenewEvent(certTyp, acmeCertName)
	return true
}

func (p *acmeImpl) publishRenewEvent(typ pb.Certificate_Type, name string) {
	switch typ {
	case pb.Certificate_ACME_NAMED,
		pb.Certificate_ACME_ON_DEMAND:
		certKey := getCertKey(typ, name)
		pubErr := p.bus.PublishCertChange(certKey, bus.ChangeType_Cert)
		if pubErr != nil {
			p.log.With(zap.Error(pubErr), zap.String("certKey", certKey)).
				Error("failed publish acme cert renew change")
		}
	default:
		p.log.Errorf("got unexpected certificate type: %v", typ)
	}
}
