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

	ocspStateMu sync.Mutex
	ocspState   map[string]*ocspState

	ocspRenewalMu sync.RWMutex
	ocspRenewal   map[string]*ocspRenewal
}

func (m *Manager) GetCertificateByName(name string) (*tls.Certificate, error) {
	helloInfo := &tls.ClientHelloInfo{ServerName: name}
	if !m.ForceRSA {
		helloInfo.SignatureSchemes = append(helloInfo.SignatureSchemes,
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		)
		helloInfo.SupportedCurves = append(helloInfo.SupportedCurves,
			tls.CurveP256, tls.CurveP384, tls.CurveP521)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	keyName := domain
	if m.ForceRSA {
		keyName += "+rsa"
	}
	m.ocspStateMu.Lock()
	if s, ok := m.ocspState[keyName]; ok {
		m.ocspStateMu.Unlock()
		s.RLock()
		defer s.RUnlock()
		return s.ocspDER, s.nextUpdate, nil
	}
	defer m.ocspStateMu.Unlock()

	// only request OCSP stapling for cached cert
	// don't request new certificate here
	_, err := m.m.Cache.Get(ctx, keyName)
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, err := m.GetCertificateByName(domain)
	if err != nil {
		return nil, time.Time{}, err
	}
	der, response, err := m.updateOCSPStapling(ctx, cert, nil)
	if err != nil {
		return nil, time.Time{}, err
	}

	issuer, _ := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
	s := &ocspState{
		leaf:       cert,
		issuer:     issuer,
		ocspDER:    der,
		nextUpdate: response.NextUpdate,
	}
	if m.ocspState == nil {
		m.ocspState = make(map[string]*ocspState)
	}
	m.ocspState[keyName] = s

	// start OCSP Stapling updater timer loop
	go func() {
		m.ocspRenewalMu.Lock()
		defer m.ocspRenewalMu.Unlock()
		if m.ocspRenewal[keyName] != nil {
			// another goroutine is already on it
			return
		}
		if m.ocspRenewal == nil {
			m.ocspRenewal = make(map[string]*ocspRenewal)
		}
		or := &ocspRenewal{m: m, keyName: keyName}
		m.ocspRenewal[keyName] = or
		or.start(s.nextUpdate)
	}()

	return s.ocspDER, s.nextUpdate, nil
}

func (m *Manager) updateOCSPStapling(ctx context.Context, cert *tls.Certificate, issuer *x509.Certificate) (der []byte, resp *ocsp.Response, err error) {
	if issuer == nil {
		issuer, err = x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
		if err != nil {
			return nil, nil, err
		}
	}
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

type ocspState struct {
	sync.RWMutex
	leaf       *tls.Certificate
	issuer     *x509.Certificate
	ocspDER    []byte
	nextUpdate time.Time
}

type ocspRenewal struct {
	m       *Manager
	keyName string

	timerMu sync.Mutex
	timer   *time.Timer
}

func (or *ocspRenewal) start(next time.Time) {
	log.Printf("starting OCSP stapling updater for key: %v\n", or.keyName)
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer != nil {
		return
	}
	or.timer = time.AfterFunc(or.next(next), or.update)
}

func (or *ocspRenewal) stop() {
	log.Printf("stoping OCSP stapling updater for key: %v\n", or.keyName)
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}
	or.timer.Stop()
	or.timer = nil
}

func (or *ocspRenewal) update() {
	log.Printf("updating OCSP stapling for key: %v\n", or.keyName)
	or.timerMu.Lock()
	defer or.timerMu.Unlock()
	if or.timer == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var next time.Duration
	// state will not be nil
	state, _ := or.m.ocspState[or.keyName]

	der, response, err := or.m.updateOCSPStapling(ctx, state.leaf, state.issuer)
	if err != nil {
		// failed
		log.Println("updateOCSPStapling failed: keyName=", or.keyName, "err=", err)
		next = renewJitter / 2
		next += time.Duration(pseudoRand.int63n(int64(next)))
	} else {
		log.Println("updateOCSPStapling success: keyName=", or.keyName, "next_update=", response.NextUpdate.Format(time.RFC3339Nano))
		// success
		state.Lock()
		defer state.Unlock()
		state.ocspDER = der
		state.nextUpdate = response.NextUpdate
		next = or.next(response.NextUpdate)
	}

	time.Sleep(10 * time.Second)

	or.timer = time.AfterFunc(next, or.update)
	testOCSPDidUpdateLoop(next, err)
}

func (or *ocspRenewal) next(expiry time.Time) time.Duration {
	log.Println("*ocspRenewal.next: key=", or.keyName, "expiry=", expiry.Format(time.RFC3339Nano))
	var d time.Duration
	if expiry.Sub(timeNow()) > 48*time.Hour {
		d = expiry.Sub(timeNow()) - 48*time.Hour
	}
	// add a bit randomness to renew deadline
	n := pseudoRand.int63n(int64(renewJitter))
	d -= time.Duration(n)
	if d < 0 {
		// force sleep a while before next update
		return time.Minute
	}
	return d
}

var testOCSPDidUpdateLoop = func(next time.Duration, err error) {}

var timeNow = time.Now
