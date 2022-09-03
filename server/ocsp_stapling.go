package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jxskiss/gopkg/v2/perf/fastrand"
	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
	"storj.io/drpc/drpcerr"

	"github.com/jxskiss/ssl-cert-server/pkg/pb"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

const (
	ocspRenewJitter = time.Hour
	ocspRenewBefore = 48 * time.Hour
)

var (
	ocspTimeNow    = time.Now
	ocspRandInt63n = fastrand.Int63n
)

type CertFunc = func() (*tls.Certificate, error)

type OCSPManager interface {
	GetOCSPStapling(ctx context.Context, key string, fp string, checkCachedCert CertFunc) (der []byte, nextUpdate time.Time, err error)
	Watch(ctx context.Context, key string, getCert CertFunc)
	NotifyCertChange(key string, getCert CertFunc)
}

func NewOCSPManager() OCSPManager {
	return &ocspManagerImpl{
		close:    make(chan struct{}),
		certMap:  make(map[string]CertFunc),
		stateMap: make(map[string]*ocspState),
		tokenMap: make(map[string]uint64),
		log:      zlog.Named("ocspManager"),
	}
}

type ocspManagerImpl struct {
	close chan struct{}

	certMu  sync.RWMutex
	certMap map[string]CertFunc

	stateMu  sync.RWMutex
	stateMap map[string]*ocspState

	tokenMu   sync.Mutex
	tokenIncr uint64
	tokenMap  map[string]uint64

	log *zap.Logger
}

func (p *ocspManagerImpl) NotifyCertChange(key string, getCert CertFunc) {
	p.certMu.Lock()
	p.certMap[key] = getCert
	p.certMu.Unlock()

	p.log.With(zap.String("key", key)).Info("received cert change event")
	ctx := context.Background()
	go p.touchState(ctx, key)
}

func (p *ocspManagerImpl) GetOCSPStapling(ctx context.Context, key string, fp string, checkCachedCert CertFunc) (der []byte, nextUpdate time.Time, err error) {
	der, nextUpdate, err = p._getOCSPStapling(key, fp)

	// If ssl-cert-server is restarted, clients may have already cached
	// the certificate, then OCSP stapling requests may arrive before
	// requesting the corresponding certificate, in which case,
	// OCSP stapling won't be cached before the certificate being loaded.
	//
	// We check for cached certificate, but don't trigger request to
	// Let's Encrypt. If we do get a cached certificate, try again to get
	// OCSP stapling.
	if err == ErrOCSPStaplingNotCached &&
		!p.isCertificateCached(key) && checkCachedCert != nil {
		_, err = checkCachedCert()
		if err == nil {
			der, nextUpdate, err = p._getOCSPStapling(key, fp)
		}
	}

	if err != nil {
		switch err {
		case ErrOCSPStaplingNotCached:
			p.log.With(zap.String("key", key)).Info("OCSP stapling is not cached")
			err = drpcerr.WithCode(err, CodeNoContent)
		default:
			p.log.With(zap.String("key", key), zap.Error(err)).
				Error("failed get OCSP stapling")
			err = drpcerr.WithCode(err, CodeInternalError)
		}
	}
	return der, nextUpdate, err
}

func (p *ocspManagerImpl) isCertificateCached(key string) bool {
	p.certMu.RLock()
	defer p.certMu.RUnlock()
	return p.certMap[key] != nil
}

func (p *ocspManagerImpl) _getOCSPStapling(key string, fp string) (der []byte, nextUpdate time.Time, err error) {
	state, ok := p.lookupState(key)
	if ok {
		if fp == "" || fp == state.certFp {
			state.RLock()
			defer state.RUnlock()
			return state.der, state.nextUpdate, nil
		}
	}
	return nil, time.Time{}, ErrOCSPStaplingNotCached
}

func (p *ocspManagerImpl) Watch(ctx context.Context, key string, getCert CertFunc) {
	p.certMu.RLock()
	if p.certMap[key] != nil {
		p.certMu.RUnlock()
		return
	}
	p.certMu.RUnlock()

	go p.watchNewCert(ctx, key, getCert)
}

func (p *ocspManagerImpl) getCertificate(key string) (*tls.Certificate, error) {
	certFunc := func() CertFunc {
		p.certMu.RLock()
		defer p.certMu.RUnlock()
		return p.certMap[key]
	}()
	if certFunc == nil {
		return nil, ErrOCSPStaplingNotCached
	}
	return certFunc()
}

func (p *ocspManagerImpl) watchNewCert(ctx context.Context, key string, getCert CertFunc) {
	p.certMu.Lock()
	if p.certMap[key] != nil {
		p.certMu.Unlock()
		return
	}
	p.certMap[key] = getCert
	p.certMu.Unlock()

	go p.touchState(ctx, key)
}

func (p *ocspManagerImpl) touchState(ctx context.Context, key string) {
	cert, err := p.getCertificate(key)
	if err != nil {
		p.log.With(zap.String("key", key), zap.Error(err)).
			Error("failed get certificate")
		return
	}
	if len(cert.Leaf.OCSPServer) == 0 {
		return
	}

	state, ok := p.lookupState(key)
	if ok {
		if bytes.Equal(state.cert.Certificate[0], cert.Certificate[0]) {
			return
		}
		// the cached state is outdated, remove it
		p.deleteState(key, state)
	}

	// allow only single worker to do request for a single certificate
	token, ok := p.markStateToken(key)
	if !ok {
		return
	}
	defer p.unmarkStateToken(key, token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		p.log.Error("failed parse certificate")
		return
	}
	der, response, err := requestOCSPStapling(ctx, cert, issuer)
	if err != nil {
		p.log.With(zap.Error(err)).Error("failed request OCSP stapling")
		return
	}
	p.log.Info("success request OCSP stapling")

	state = p.setState(key, cert, issuer, der, response)
	return
}

func (p *ocspManagerImpl) markStateToken(key string) (token uint64, ok bool) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	if _, ok := p.tokenMap[key]; ok {
		return 0, false
	}
	token = atomic.AddUint64(&p.tokenIncr, 1)
	p.tokenMap[key] = token
	return token, true
}

func (p *ocspManagerImpl) unmarkStateToken(key string, token uint64) {
	p.stateMu.Lock()
	if tok, ok := p.tokenMap[key]; ok && token == tok {
		delete(p.tokenMap, key)
	}
	p.stateMu.Unlock()
}

func (p *ocspManagerImpl) lookupState(key string) (*ocspState, bool) {
	p.stateMu.RLock()
	state, ok := p.stateMap[key]
	p.stateMu.RUnlock()
	return state, ok
}

func (p *ocspManagerImpl) deleteState(key string, state *ocspState) {
	p.stateMu.Lock()
	curState, ok := p.stateMap[key]
	if ok && state == curState {
		delete(p.stateMap, key)
	}
	p.stateMu.Unlock()

	if state.renewal != nil {
		state.renewal.stop()
	}
}

func (p *ocspManagerImpl) setState(key string, cert *tls.Certificate, issuer *x509.Certificate, der []byte, response *ocsp.Response) *ocspState {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()

	fp := utils.CalcCertFingerprint(cert.Leaf)
	renewal := newOCSPRenewal(p, key)
	state := &ocspState{
		cert:       cert,
		issuer:     issuer,
		certFp:     fp,
		der:        der,
		nextUpdate: response.NextUpdate,
		renewal:    renewal,
	}
	p.stateMap[key] = state

	// start OCSP stapling renewal timer loop
	go renewal.start(state.nextUpdate)
	return state
}

// -------- ocsp state & renewal -------- //

type ocspState struct {
	sync.RWMutex
	cert       *tls.Certificate
	issuer     *x509.Certificate
	certFp     string
	der        []byte
	nextUpdate time.Time
	renewal    *ocspRenewal
}

type ocspRenewal struct {
	mgr *ocspManagerImpl
	key string

	timerMu sync.Mutex
	timer   *time.Timer

	log *zap.Logger
}

func newOCSPRenewal(m *ocspManagerImpl, key string) *ocspRenewal {
	return &ocspRenewal{
		mgr: m,
		key: key,
		log: zlog.Named("ocspRenewal").With(zap.String("key", key)),
	}
}

func (or *ocspRenewal) start(next time.Time) {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer != nil {
		return
	}
	or.timer = time.AfterFunc(or.next(next), or.update)
	or.log.With(zap.Time("nextUpdate", next)).
		Info("started OCSP stapling renewal")
}

func (or *ocspRenewal) stop() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}
	or.timer.Stop()
	or.timer = nil
	or.log.Info("stopped OCSP stapling renewal")
}

func (or *ocspRenewal) update() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}

	state, ok := or.mgr.lookupState(or.key)
	if !ok || state.renewal != or {
		// state has been removed / replaced, stop the old renewal
		or.timer = nil
		return
	}
	if len(state.cert.Leaf.OCSPServer) == 0 {
		return
	}

	var next time.Duration
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	der, response, err := requestOCSPStapling(ctx, state.cert, state.issuer)
	if err != nil {
		or.log.With(zap.Error(err)).Error("failed request OCSP stapling")
		next = ocspRenewJitter / 2
		next += time.Duration(ocspRandInt63n(int64(next)))
	} else {
		or.log.With(zap.Time("nextUpdate", response.NextUpdate)).
			Info("success request OCSP stapling")
		state.Lock()
		defer state.Unlock()
		state.der = der
		state.nextUpdate = response.NextUpdate
		next = or.next(response.NextUpdate)
	}

	or.timer = time.AfterFunc(next, or.update)
}

func (or *ocspRenewal) next(expiry time.Time) time.Duration {
	var d time.Duration
	if ttl := expiry.Sub(ocspTimeNow()); ttl > ocspRenewBefore {
		d = ttl - ocspRenewBefore
	}
	// add a bit of randomness to renew deadline
	n := ocspRandInt63n(int64(ocspRenewJitter))
	d -= time.Duration(n)

	// force sleep at least one minute before next update
	if d < time.Minute {
		n = ocspRandInt63n(int64(time.Minute))
		d = time.Minute + time.Duration(n)
	}
	return d
}

func requestOCSPStapling(ctx context.Context, cert *tls.Certificate, issuer *x509.Certificate) (der []byte, resp *ocsp.Response, err error) {
	ocspReq, err := ocsp.CreateRequest(cert.Leaf, issuer, nil)
	if err != nil {
		return nil, nil, err
	}
	httpReq, err := http.NewRequest("POST", cert.Leaf.OCSPServer[0], bytes.NewBuffer(ocspReq))
	if err != nil {
		return nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpResp, err := http.DefaultClient.Do(httpReq.WithContext(ctx))
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close()
	der, err = io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp, err = ocsp.ParseResponse(der, issuer)
	if err != nil {
		return nil, nil, err
	}
	return der, resp, nil
}

func getOCSPKey(typ pb.Certificate_Type, name string) string {
	return fmt.Sprintf("%d:%s", int(typ), name)
}
