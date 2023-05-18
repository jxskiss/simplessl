package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/atomic"
	"go.uber.org/zap"

	"github.com/jxskiss/ssl-cert-server/pkg/bus"
	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/pb"
)

type ManagedCertManager interface {
	GetCertificate(ctx context.Context, name string) (*tls.Certificate, error)
}

func NewManagedCertManager(
	cfg *config.Config,
	bus bus.EventBus,
	storage StorageManager,
	ocspMgr OCSPManager,
) ManagedCertManager {
	return &managedCertMgrImpl{
		cfg:  cfg,
		bus:  bus,
		stor: storage,
		ocsp: ocspMgr,
		log:  zlog.Named("managed").Sugar(),
	}
}

type managedCertMgrImpl struct {
	cache sync.Map

	cfg  *config.Config
	bus  bus.EventBus
	stor StorageManager
	ocsp OCSPManager

	log *zap.SugaredLogger
}

func (p *managedCertMgrImpl) GetCertificate(ctx context.Context, name string) (*tls.Certificate, error) {
	cert, err := p._getCertificate(ctx, name)
	if err != nil {
		return nil, err
	}

	if p.cfg.IsManagedCertEnableOCSPStapling(name) {
		certKey := getCertKey(pb.Certificate_MANAGED, name)
		p.ocsp.Watch(ctx, certKey, func() (*tls.Certificate, error) {
			// When watching from certificate manager,
			// there is no need to trigger watching again,
			// use the internal method here.
			return p._getCertificate(context.Background(), name)
		})
	}

	return cert, nil
}

func (p *managedCertMgrImpl) _getCertificate(ctx context.Context, name string) (*tls.Certificate, error) {
	cached, ok := p.cache.Load(name)
	if !ok {
		cached, _ = p.cache.LoadOrStore(name, &managedCert{
			mgr:  p,
			name: name,
		})
	}
	return cached.(*managedCert).getAndCheckReload(ctx)
}

type managedCert struct {
	mgr  *managedCertMgrImpl
	name string

	sync.Mutex
	cert     atomic.UnsafePointer // *tls.Certificate
	loadMsec int64
}

func (p *managedCert) getAndCheckReload(ctx context.Context) (*tls.Certificate, error) {
	cert := p.cert.Load()
	if cert != nil {
		if p.loadMsec > 0 &&
			time.Since(time.UnixMilli(p.loadMsec)) > p.mgr.cfg.GetManagedCertReloadInterval() {
			go p.reload(ctx)
		}
		return (*tls.Certificate)(cert), nil
	}

	// cache not ready, lock and load from storage
	p.Lock()
	defer p.Unlock()
	if cert := p.cert.Load(); cert != nil {
		return (*tls.Certificate)(cert), nil
	}

	tlscert, _, _, err := p.mgr.stor.LoadCertificate(ctx, pb.Certificate_MANAGED, p.name)
	if err != nil {
		return nil, fmt.Errorf("managed: %w", err)
	}

	p.mgr.log.Infof("load certificate from storage, name= %v, notAfter= %v",
		p.name, tlscert.Leaf.NotAfter)
	p.cert.Store(unsafe.Pointer(tlscert))
	p.loadMsec = time.Now().UnixMilli()
	return tlscert, nil
}

func (p *managedCert) reload(ctx context.Context) {
	tlscert, _, _, err := p.mgr.stor.LoadCertificate(ctx, pb.Certificate_MANAGED, p.name)
	if err != nil {
		p.mgr.log.With(zap.String("name", p.name), zap.Error(err)).
			Error("failed reload certificate")
		return
	}

	p.mgr.log.Infof("reload certificate from storage, name= %v, notAfter= %v",
		p.name, tlscert.Leaf.NotAfter)

	p.Lock()
	p.cert.Store(unsafe.Pointer(tlscert))
	p.loadMsec = time.Now().UnixMilli()
	p.Unlock()

	certName := p.name
	certKey := getCertKey(pb.Certificate_MANAGED, certName)
	p.mgr.ocsp.NotifyCertChange(certKey, func() (*tls.Certificate, error) {
		return p.mgr._getCertificate(context.Background(), certName)
	})

	pubErr := p.mgr.bus.PublishCertChange(certKey, bus.ChangeType_Cert)
	if pubErr != nil {
		p.mgr.log.With(zap.Error(pubErr), zap.String("certKey", certKey)).
			Error("failed publish managed cert reload change")
	}
}
