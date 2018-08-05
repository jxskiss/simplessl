package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ocsp"
)

// renewJitter is the maximum deviation from Manager.RenewBefore.
const renewJitter = time.Hour

// pseudoRand is safe for concurrent use.
var pseudoRand *lockedMathRand

// httpClient is used to do http request instead of the default http.DefaultClient.
// The OCSP server of Let's Encrypt certificates seems working improperly, gives
// `Unsolicited response received on idle HTTP channel starting with "HTTP/1.0 408 Request Time-out"`
// errors constantly after the service has been running for a long time.
// Using custom httpClient which disables Keep-Alive should fix this issue.
var httpClient *http.Client

func init() {
	pseudoRand = &lockedMathRand{rnd: mathrand.New(mathrand.NewSource(timeNow().UnixNano()))}
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				DualStack: true,
			}).DialContext,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

var ErrHostNotPermitted = errors.New("host not permitted")

func HostWhitelist(hosts ...string) autocert.HostPolicy {
	whitelist := autocert.HostWhitelist(hosts...)
	return func(ctx context.Context, host string) error {
		if whitelist(ctx, host) != nil {
			return ErrHostNotPermitted
		}
		return nil
	}
}

func RegexpWhitelist(patterns ...*regexp.Regexp) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		for _, p := range patterns {
			if p.MatchString(host) {
				return nil
			}
		}
		return ErrHostNotPermitted
	}
}

func EncodeRSAKey(w io.Writer, key *rsa.PrivateKey) error {
	b := x509.MarshalPKCS1PrivateKey(key)
	pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func EncodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

type Manager struct {
	m        *autocert.Manager
	ForceRSA bool

	ocspStateMu sync.RWMutex
	ocspState   map[string]*ocspState
}

func (m *Manager) GetCertificateByName(name string) (*tls.Certificate, error) {
	helloInfo := &tls.ClientHelloInfo{ServerName: name}
	if !m.ForceRSA {
		helloInfo.SignatureSchemes = append(helloInfo.SignatureSchemes,
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		)
		helloInfo.SupportedCurves = append(helloInfo.SupportedCurves, tls.CurveP256, tls.CurveP384, tls.CurveP521)
		helloInfo.CipherSuites = append(helloInfo.CipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		)
	}
	return m.m.GetCertificate(helloInfo)
}

func (m *Manager) GetOCSPStapling(domain string) ([]byte, time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyName := domain
	if m.ForceRSA {
		keyName += "+rsa"
	}
	m.ocspStateMu.Lock()
	defer m.ocspStateMu.Unlock()
	state, exists := m.ocspState[keyName]
	// only request OCSP stapling for cached certificate
	if !exists {
		if _, err := m.m.Cache.Get(ctx, keyName); err != nil {
			return nil, time.Time{}, err
		}
	}
	cert, err := m.GetCertificateByName(domain)
	if err != nil {
		return nil, time.Time{}, err
	}
	if exists {
		//if state.cert.Leaf == cert.Leaf {}
		if bytes.Equal(state.cert.Certificate[0], cert.Certificate[0]) {
			state.RLock()
			defer state.RUnlock()
			return state.ocspDER, state.nextUpdate, nil
		} else {
			state.renewal.stop()
			delete(m.ocspState, keyName)
		}
	}

	issuer, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
	if err != nil {
		return nil, time.Time{}, err
	}
	der, response, err := m.updateOCSPStapling(ctx, cert, issuer)
	if err != nil {
		return nil, time.Time{}, err
	}
	state = &ocspState{
		cert:       cert,
		issuer:     issuer,
		ocspDER:    der,
		nextUpdate: response.NextUpdate,
		renewal:    &ocspRenewal{m: m, domain: domain, keyName: keyName},
	}
	if m.ocspState == nil {
		m.ocspState = make(map[string]*ocspState)
	}
	m.ocspState[keyName] = state

	// start OCSP stapling renewal timer loop
	go state.renewal.start(state.nextUpdate)

	return state.ocspDER, state.nextUpdate, nil
}

func (m *Manager) updateOCSPStapling(ctx context.Context, cert *tls.Certificate, issuer *x509.Certificate) (der []byte, resp *ocsp.Response, err error) {
	ocspReq, err := ocsp.CreateRequest(cert.Leaf, issuer, nil)
	if err != nil {
		return nil, nil, err
	}
	httpResp, err := httpClient.Post(cert.Leaf.OCSPServer[0], "application/ocsp-request", bytes.NewBuffer(ocspReq))
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close()
	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, nil, err
	}
	resp, err = ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, nil, err
	}
	return body, resp, nil
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
	m       *Manager
	domain  string
	keyName string

	timerMu sync.Mutex
	timer   *time.Timer
}

func (or *ocspRenewal) start(next time.Time) {
	log.Println("starting OCSP stapling renewal: key_name=", or.keyName, "next_update=", next.Format(time.RFC3339Nano))
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer != nil {
		return
	}
	or.timer = time.AfterFunc(or.next(next), or.update)
}

func (or *ocspRenewal) stop() {
	log.Println("stoping OCSP stapling renewal: key_name=", or.keyName)
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}
	or.timer.Stop()
	or.timer = nil
}

func (or *ocspRenewal) update() {
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil { // has been stopped
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	or.m.ocspStateMu.RLock()
	state, ok := or.m.ocspState[or.keyName]
	or.m.ocspStateMu.RUnlock()
	if !ok || state.renewal != or {
		// state has been removed / replaced, stop the old renewal and trigger
		// caching OCSP stapling for the new certificate
		or.timer = nil
		go or.m.GetOCSPStapling(or.domain)
		return
	}

	var next time.Duration
	der, response, err := or.m.updateOCSPStapling(ctx, state.cert, state.issuer)
	if err != nil {
		log.Println("update OCSP stapling failed: key_name=", or.keyName, "err=", err)
		next = renewJitter / 2
		next += time.Duration(pseudoRand.int63n(int64(next)))
	} else {
		log.Println("update OCSP stapling success: key_name=", or.keyName, "next_update=", response.NextUpdate.Format(time.RFC3339Nano))
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
	if expiry.Sub(timeNow()) > 48*time.Hour {
		d = expiry.Sub(timeNow()) - 48*time.Hour
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

type lockedMathRand struct {
	sync.Mutex
	rnd *mathrand.Rand
}

func (r *lockedMathRand) int63n(max int64) int64 {
	r.Lock()
	n := r.rnd.Int63n(max)
	r.Unlock()
	return n
}

var testOCSPDidUpdateLoop = func(next time.Duration, err error) {}

var timeNow = time.Now
