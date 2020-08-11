package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	certsCheckInterval = time.Second
	renewJitter        = time.Hour
	renewBefore        = time.Hour * 48
)

var (
	ErrStaplingNotCached = errors.New("OCSP stapling is not cached")
	ErrCertfuncNotFound  = errors.New("certificate func not found") // TODO: check this error
)

var OCSPManager = &ocspManager{}

func init() {
	OCSPManager.certKeys.Store(make(map[string]func() (*tls.Certificate, error)))
	OCSPManager.stateMap = make(map[string]*ocspState)
	OCSPManager.stateToken = make(map[string]struct{})
	go OCSPManager.listenCertChanges()
}

type ocspManager struct {
	// copy-on-write map
	certMu   sync.Mutex
	certKeys atomic.Value // map[string]func() (*tls.Certificate, error)

	stateMu    sync.RWMutex
	stateMap   map[string]*ocspState
	stateToken map[string]struct{}
}

func (m *ocspManager) GetOCSPStapling(keyName string, fingerprint string) ([]byte, time.Time, error) {
	state, ok := m.lookupState(keyName)
	if ok {
		fp := sha1.Sum(state.cert.Leaf.Raw)
		if fingerprint == "" || fingerprint == hex.EncodeToString(fp[:]) {
			state.RLock()
			defer state.RUnlock()
			return state.ocspDER, state.nextUpdate, nil
		}
	}

	log.Printf("[INFO] ocsp manager: OCSP stapling not cached: key_name= %v", keyName)
	go m.touchState(keyName)

	// don't block request
	return nil, time.Time{}, ErrStaplingNotCached
}

func (m *ocspManager) Watch(keyName string, certfunc func() (*tls.Certificate, error)) {
	certMap := m.getCertMap()
	if certMap[keyName] != nil {
		return
	}
	go m.cowCertMap(keyName, certfunc)
}

func (m *ocspManager) getCertMap() map[string]func() (*tls.Certificate, error) {
	return m.certKeys.Load().(map[string]func() (*tls.Certificate, error))
}

func (m *ocspManager) cowCertMap(keyName string, certfunc func() (*tls.Certificate, error)) {
	m.certMu.Lock()
	defer m.certMu.Unlock()
	oldCertMap := m.getCertMap()
	newCertMap := make(map[string]func() (*tls.Certificate, error), len(oldCertMap)+1)
	for k, f := range oldCertMap {
		newCertMap[k] = f
	}
	newCertMap[keyName] = certfunc
	m.certKeys.Store(newCertMap)
}

func (m *ocspManager) getCertificate(keyName string) (*tls.Certificate, error) {
	certfunc := m.getCertMap()[keyName]
	if certfunc != nil {
		return certfunc()
	}
	return nil, ErrCertfuncNotFound
}

func (m *ocspManager) listenCertChanges() {
	// at most 50 concurrent goroutines
	token := make(chan struct{}, 50)
	ticker := time.NewTicker(certsCheckInterval)
	for range ticker.C {
		certMap := m.getCertMap()
		keyNames := make([]string, 0, len(certMap))
		for keyName := range certMap {
			keyNames = append(keyNames, keyName)
		}
		for _, keyName := range keyNames {
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
// server and cache the stateMap in Manager.
func (m *ocspManager) touchState(keyName string) {
	cert, err := m.getCertificate(keyName)
	if err != nil {
		log.Printf("[ERROR] ocsp manager: failed get certifcate: key_name= %s err= %v", keyName, err)
		return
	}
	state, ok := m.lookupState(keyName)
	if ok {
		if bytes.Equal(state.cert.Certificate[0], cert.Certificate[0]) {
			return
		}
		// the cached state is outdated, remove it
		state.renewal.stop()
		m.deleteState(keyName)
	}

	// allow only single worker to do request for a single certificate
	if !m.markStateToken(keyName) {
		return
	}
	defer m.unmarkStateToken(keyName)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	issuer, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
	if err != nil {
		log.Printf("[ERROR] ocsp manager: failed parse certificate: key_name= %s err= %v", keyName, err)
		return
	}
	der, response, err := requestOCSPStapling(ctx, cert, issuer)
	if err != nil {
		log.Printf("[ERROR] ocsp manager: failed request OCSP stapling: key_name= %s, err= %v", keyName, err)
		return
	}
	state = m.setState(keyName, cert, issuer, der, response)
	return
}

func (m *ocspManager) markStateToken(keyName string) bool {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if _, ok := m.stateToken[keyName]; ok {
		return false
	}
	m.stateToken[keyName] = struct{}{}
	return true
}

func (m *ocspManager) unmarkStateToken(keyName string) {
	m.stateMu.Lock()
	delete(m.stateToken, keyName)
	m.stateMu.Unlock()
}

func (m *ocspManager) lookupState(keyName string) (*ocspState, bool) {
	m.stateMu.RLock()
	state, ok := m.stateMap[keyName]
	m.stateMu.RUnlock()
	return state, ok
}

func (m *ocspManager) deleteState(keyName string) {
	m.stateMu.Lock()
	delete(m.stateMap, keyName)
	m.stateMu.Unlock()
}

func (m *ocspManager) setState(
	keyName string,
	cert *tls.Certificate,
	issuer *x509.Certificate,
	der []byte,
	response *ocsp.Response,
) *ocspState {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	renewal := &ocspRenewal{manager: m, keyName: keyName}
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
	manager *ocspManager
	keyName string

	timerMu sync.Mutex
	timer   *time.Timer
}

func (or *ocspRenewal) start(next time.Time) {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer != nil {
		return
	}
	or.timer = time.AfterFunc(or.next(next), or.update)
	log.Printf("[INFO] ocsp renewal: started OCSP stapling renewal: key_name= %s next_update= %s", or.keyName, next.Format(time.RFC3339Nano))
}

func (or *ocspRenewal) stop() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}
	or.timer.Stop()
	or.timer = nil
	log.Printf("[INFO] ocsp renewal: stoped OCSP stapling renewal: key_name= %s", or.keyName)
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

	var next time.Duration
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	der, response, err := requestOCSPStapling(ctx, state.cert, state.issuer)
	if err != nil {
		log.Printf("[ERROR] ocsp renewal: failed request OCSP stapling: key_name= %s err= %v", or.keyName, err)
		next = renewJitter / 2
		next += time.Duration(pseudoRand.int63n(int64(next)))
	} else {
		log.Printf("[INFO] ocsp renewal: request OCSP stapling success: key_name= %s next_update= %s", or.keyName, response.NextUpdate.Format(time.RFC3339Nano))
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
	if ttl := expiry.Sub(timeNow()); ttl > renewBefore {
		d = ttl - renewBefore
	}
	// add a bit randomness to renew deadline
	n := pseudoRand.int63n(int64(renewJitter))
	d -= time.Duration(n)
	if d < 0 {
		// force sleep a while before next update
		n := pseudoRand.int63n(int64(time.Minute))
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
	der, err = ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp, err = ocsp.ParseResponse(der, issuer)
	if err != nil {
		return nil, nil, err
	}
	return der, resp, nil
}
