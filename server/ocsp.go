package server

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

const (
	certsCheckInterval = time.Second
	renewJitter        = time.Hour
	renewBefore        = time.Hour * 48
)

var (
	ErrOCSPStateNotCached = errors.New("OCSP state is not cached")
	ErrOCSPNotSupported   = errors.New("OCSP stapling is not supported")
	ErrStaplingNotCached  = errors.New("OCSP stapling is not cached")
	ErrCertfuncNotFound   = errors.New("certificate func not found")
)

func NewOCSPManager() *OCSPManager {
	mgr := &OCSPManager{
		stateMap:   make(map[string]*ocspState),
		stateToken: make(map[string]uint64),
		log:        zlog.Named("ocspManager").Sugar(),
	}
	certMap := make(map[string]func() (*tls.Certificate, error))
	mgr.certMap.Store(certMap)
	go mgr.listenCertChanges()
	return mgr
}

type OCSPManager struct {
	// copy-on-write map
	certMu  sync.Mutex
	certMap atomic.Value // map[string]func() (*tls.Certificate, error)

	stateMu    sync.RWMutex
	stateMap   map[string]*ocspState
	stateToken map[string]uint64

	tokenIncr uint64

	log *zap.SugaredLogger
}

func (m *OCSPManager) GetOCSPStapling(
	keyName string,
	fingerprint string,
	checkCacheCert func() (*tls.Certificate, error),
) ([]byte, time.Time, error) {
	ocspDER, nextUpdate, err := m._getOCSPStapling(keyName, fingerprint)

	// If ssl-cert-server was restarted, clients may have already cached
	// the certificate, then OCSP stapling requests may arrive before
	// requesting the corresponding certificate, in which case,
	// OCSP stapling won't be cached before the certificate being loaded.
	//
	// We check for cached certificate, but don't trigger request to
	// Let's Encrypt. If we do get a cached certificate, try again to get
	// OCSP stapling.
	if err == ErrOCSPStateNotCached &&
		!m.IsCertificateCached(keyName) && checkCacheCert != nil {
		_, err = checkCacheCert()
		if err == nil {
			ocspDER, nextUpdate, err = m._getOCSPStapling(keyName, fingerprint)
		}
	}

	if err != nil {
		switch err {
		case ErrOCSPNotSupported:
			m.log.Infof("OCSP staplign is not supported: keyName= %s", keyName)
		case ErrOCSPStateNotCached:
			m.log.Infof("OCSP state is not cached: keyName= %s", keyName)
		case ErrStaplingNotCached:
			m.log.Infof("OCSP stapling is not cached: keyName= %s", keyName)
		default:
			m.log.Infof("failed get OCSP stapling: keyName= %s err= %v", keyName, err)
		}
	}
	return ocspDER, nextUpdate, err
}

func (m *OCSPManager) _getOCSPStapling(keyName string, fingerprint string) ([]byte, time.Time, error) {
	state, ok := m.lookupState(keyName)
	if ok {
		fp := sha1.Sum(state.cert.Leaf.Raw)
		if fingerprint == "" || fingerprint == hex.EncodeToString(fp[:]) {
			state.RLock()
			defer state.RUnlock()
			return state.ocspDER, state.nextUpdate, nil
		}
		return nil, time.Time{}, ErrStaplingNotCached
	}
	return nil, time.Time{}, ErrOCSPStateNotCached
}

func (m *OCSPManager) Watch(keyName string, certfunc func() (*tls.Certificate, error)) {
	certMap := m.getCertMap()
	if certMap[keyName] != nil {
		return
	}
	go m.watchNewCert(keyName, certfunc)
}

func (m *OCSPManager) IsCertificateCached(keyName string) bool {
	return m.getCertMap()[keyName] != nil
}

func (m *OCSPManager) getCertMap() map[string]func() (*tls.Certificate, error) {
	return m.certMap.Load().(map[string]func() (*tls.Certificate, error))
}

func (m *OCSPManager) watchNewCert(keyName string, certfunc func() (*tls.Certificate, error)) {
	m.certMu.Lock()
	defer m.certMu.Unlock()
	oldCertMap := m.getCertMap()
	newCertMap := make(map[string]func() (*tls.Certificate, error), len(oldCertMap)+1)
	for k, f := range oldCertMap {
		newCertMap[k] = f
	}
	newCertMap[keyName] = certfunc
	m.certMap.Store(newCertMap)

	go m.touchState(keyName)
}

func (m *OCSPManager) getCertificate(keyName string) (*tls.Certificate, error) {
	certfunc := m.getCertMap()[keyName]
	if certfunc != nil {
		return certfunc()
	}
	return nil, ErrCertfuncNotFound
}

func (m *OCSPManager) listenCertChanges() {
	// at most 50 concurrent goroutines
	token := make(chan struct{}, 50)
	ticker := time.NewTicker(certsCheckInterval)
	for range ticker.C {
		certMap := m.getCertMap()
		for keyName := range certMap {
			token <- struct{}{}
			go func(keyName string) {
				defer func() { <-token }()
				m.touchState(keyName)
			}(keyName)
		}
	}
}

// touchState checks if OCSP stapling state for the given keyName is cached.
// If not, it will request the OCSP stapling from the certificate's OCSP
// server and cache the stateMap in OCSPManager.
func (m *OCSPManager) touchState(keyName string) {
	cert, err := m.getCertificate(keyName)
	if err != nil {
		m.log.Errorf("failed get certifcate: keyName= %s err= %v", keyName, err)
		return
	}
	if len(cert.Leaf.OCSPServer) == 0 {
		return
	}

	state, ok := m.lookupState(keyName)
	if ok {
		if bytes.Equal(state.cert.Certificate[0], cert.Certificate[0]) {
			return
		}
		// the cached state is outdated, remove it
		m.deleteState(keyName, state)
	}

	// allow only single worker to do request for a single certificate
	token, ok := m.markStateToken(keyName)
	if !ok {
		return
	}
	defer m.unmarkStateToken(keyName, token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	issuer, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		m.log.Errorf("failed parse certificate: keyName= %s err= %v", keyName, err)
		return
	}
	der, response, err := requestOCSPStapling(ctx, cert, issuer)
	if err != nil {
		m.log.Errorf("failed request OCSP stapling: keyName= %s err= %v", keyName, err)
		return
	}
	m.log.Infof("request OCSP stapling success: keyName= %s", keyName)
	state = m.setState(keyName, cert, issuer, der, response)
	return
}

func (m *OCSPManager) markStateToken(keyName string) (token uint64, ok bool) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if _, ok := m.stateToken[keyName]; ok {
		return 0, false
	}
	token = atomic.AddUint64(&m.tokenIncr, 1)
	m.stateToken[keyName] = token
	return token, true
}

func (m *OCSPManager) unmarkStateToken(keyName string, token uint64) {
	m.stateMu.Lock()
	if lockToken, ok := m.stateToken[keyName]; ok && token == lockToken {
		delete(m.stateToken, keyName)
	}
	m.stateMu.Unlock()
}

func (m *OCSPManager) lookupState(keyName string) (*ocspState, bool) {
	m.stateMu.RLock()
	state, ok := m.stateMap[keyName]
	m.stateMu.RUnlock()
	return state, ok
}

func (m *OCSPManager) deleteState(keyName string, state *ocspState) {
	if state.renewal != nil {
		state.renewal.stop()
	}
	m.stateMu.Lock()
	oldState, ok := m.stateMap[keyName]
	if ok && state == oldState {
		delete(m.stateMap, keyName)
	}
	m.stateMu.Unlock()
}

func (m *OCSPManager) setState(
	keyName string,
	cert *tls.Certificate,
	issuer *x509.Certificate,
	der []byte,
	response *ocsp.Response,
) *ocspState {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	renewal := newOCSPRenewal(m, keyName)
	state := &ocspState{
		cert:       cert,
		issuer:     issuer,
		ocspDER:    der,
		nextUpdate: response.NextUpdate,
		renewal:    renewal,
	}
	m.stateMap[keyName] = state

	// start OCSP stapling renewal timer loop
	go renewal.start(state.nextUpdate)
	return state
}

type ocspState struct {
	sync.RWMutex
	cert       *tls.Certificate
	issuer     *x509.Certificate
	ocspDER    []byte
	nextUpdate time.Time
	renewal    *ocspRenewal
}

type ocspRenewal struct {
	manager *OCSPManager
	keyName string

	timerMu sync.Mutex
	timer   *time.Timer

	log *zap.SugaredLogger
}

func newOCSPRenewal(mgr *OCSPManager, keyName string) *ocspRenewal {
	return &ocspRenewal{
		manager: mgr,
		keyName: keyName,
		log:     zlog.Named("ocspRenewal").Sugar(),
	}
}

func (or *ocspRenewal) start(next time.Time) {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer != nil {
		return
	}
	or.timer = time.AfterFunc(or.next(next), or.update)
	or.log.Infof("started OCSP stapling renewal: keyName= %s nextUpdate= %s", or.keyName, next.Format(time.RFC3339Nano))
}

func (or *ocspRenewal) stop() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}
	or.timer.Stop()
	or.timer = nil
	or.log.Infof("stopped OCSP stapling renewal: keyName= %s", or.keyName)
}

func (or *ocspRenewal) update() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil { // has been stopped
		return
	}

	state, ok := or.manager.lookupState(or.keyName)
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
		or.log.Errorf("failed request OCSP stapling: keyName= %s err= %v", or.keyName, err)
		next = renewJitter / 2
		next += time.Duration(rand63n(int64(next)))
	} else {
		or.log.Infof("request OCSP stapling success: keyName= %s nextUpdate= %s", or.keyName, response.NextUpdate.Format(time.RFC3339Nano))
		state.Lock()
		defer state.Unlock()
		state.ocspDER = der
		state.nextUpdate = response.NextUpdate
		next = or.next(response.NextUpdate)
	}

	or.timer = time.AfterFunc(next, or.update)
	testOCSPDidUpdateLoop(next, err)
}

func (or *ocspRenewal) next(expiry time.Time) time.Duration {
	var d time.Duration
	if ttl := expiry.Sub(ocspTimeNow()); ttl > renewBefore {
		d = ttl - renewBefore
	}
	// add a bit randomness to renew deadline
	n := rand63n(int64(renewJitter))
	d -= time.Duration(n)

	// force sleep at least one minute before next update
	if d < time.Minute {
		n = rand63n(int64(time.Minute))
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
	httpResp, err := httpClient.Do(httpReq.WithContext(ctx))
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
