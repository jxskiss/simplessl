package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"golang.org/x/net/idna"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

// Certificate types
//
// - smaller than 100 for certificates which have OCSP stapling;
// - equal or larger than 100 for certificates which don't have OCSP stapling;
const (
	LetsEncrypt = 0
	Managed     = 1
	Wildcard    = 2
	SelfSigned  = 100
	ALPNCert    = 101
)

var (
	RspInvalidDomainName     = []byte("Invalid domain name.")
	RspHostNotPermitted      = []byte("Host name not permitted.")
	RspCertificateIsExpired  = []byte("Certificate is expired.")
	RspErrGetCertificate     = []byte("Error getting certificate.")
	RspErrMarshalCertificate = []byte("Error marshal certificate.")
)

func (m *Manager) BuildRoutes(mux *http.ServeMux) {
	accessLogger := zlog.Named("access").Sugar()
	var _mw = func(h http.Handler) http.Handler {
		return loggingMiddleware(accessLogger, recoverMiddleware(m.log, h))
	}
	mux.Handle("/cert/", _mw(http.HandlerFunc(m.HandleCertificate)))
	mux.Handle("/ocsp/", _mw(http.HandlerFunc(m.HandleOCSPStapling)))
	mux.Handle("/.well-known/acme-challenge/", _mw(m.autocert.HTTPHandler(nil)))
}

// HandleCertificate handlers requests of SSL certificate.
//
// Possible responses are:
// - 200 with the certificate data as response
// - 400 the requested domain name is invalid or not permitted
// - 500 which indicates the server failed to process the request,
//       in such case, the body will be filled with the error message
func (m *Manager) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	domain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		m.log.Infof("got invalid domain name: err= %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}

	var tlscert *tls.Certificate
	var certType int
	var isALPN01 = r.URL.Query().Get("alpn") == "1"
	if isALPN01 {
		certType = ALPNCert
		tlscert, err = m.GetAutocertALPN01Certificate(domain)
	} else {
		tlscert, certType, err = m.GetCertificateByName(domain)
	}
	if err != nil {
		if err == ErrHostNotPermitted {
			m.log.Infof("domain name not permitted: domain= %s", domain)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(RspHostNotPermitted)
		} else {
			m.log.Errorf("failed get certificate: domain= %s err= %v", domain, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrGetCertificate)
		}
		return
	}

	var ttlSeconds int
	if !isALPN01 {
		var ttl = time.Until(tlscert.Leaf.NotAfter)
		if ttl <= 0 {
			m.log.Warnf("got expired certificate: domain= %s", domain)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspCertificateIsExpired)
			return
		}
		ttlSeconds = m.limitTTL(ttl)
	}
	response, err := marshalCertificate(tlscert, certType, ttlSeconds)
	if err != nil {
		m.log.Errorf("failed marshal certificate: domain= %s err= %v", domain, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(RspErrMarshalCertificate)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func marshalCertificate(cert *tls.Certificate, certType int, ttl int) ([]byte, error) {
	var (
		err        error
		certBuf    bytes.Buffer
		privKeyBuf bytes.Buffer
	)
	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err = pem.Encode(&certBuf, pb); err != nil {
			return nil, fmt.Errorf("encode certificate: %v", err)
		}
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = utils.EncodeRSAKey(&privKeyBuf, key)
	case *ecdsa.PrivateKey:
		err = utils.EncodeECDSAKey(&privKeyBuf, key)
	default:
		err = fmt.Errorf("unknown private key type")
	}
	if err != nil {
		return nil, fmt.Errorf("encode private key: %v", err)
	}

	// Leaf and fingerprint are not needed for tls-alpn-01 certificate.
	var fingerprint string
	var expireAt int64
	if cert.Leaf != nil {
		fingerprint = utils.CalcCertFingerprint(cert.Leaf)
	}
	response := struct {
		Type        int    `json:"type"`
		Cert        string `json:"cert"`
		PKey        string `json:"pkey"`
		Fingerprint string `json:"fingerprint"`
		ExpireAt    int64  `json:"expire_at"` // seconds since epoch
		TTL         int    `json:"ttl"`       // in seconds
	}{
		Type:        certType,
		Cert:        string(certBuf.Bytes()),
		PKey:        string(privKeyBuf.Bytes()),
		Fingerprint: fingerprint,
		ExpireAt:    expireAt,
		TTL:         ttl,
	}
	return json.Marshal(response)
}

func (m *Manager) GetCertificateByName(name string) (tlscert *tls.Certificate, certType int, err error) {
	// check managed domains first
	if certKey, ok := IsManagedDomain(name); ok {
		certType = Managed
		tlscert, err = m.managed.Get(certKey)
	} else
	// check wildcard domains
	if wcItem, ok := IsWildcardDomain(name); ok {
		certType = Wildcard
		tlscert, err = m.wildcard.Get(wcItem, true)
	} else
	// check concrete domains
	if err = m.autocert.HostPolicy(context.Background(), name); err == nil {
		certType = LetsEncrypt
		tlscert, err = m.GetAutocertCertificate(name)
	} else
	// check self-signed
	if IsSelfSignedAllowed(name) {
		certType = SelfSigned
		tlscert, err = GetSelfSignedCertificate()
	} else
	// host not allowed
	{
		err = ErrHostNotPermitted
	}
	return
}

// HandleOCSPStapling handles requests of OCSP stapling.
//
// Possible responses are:
// - 200 with the OCSP response as body
// - 204 without body, which indicates OCSP stapling for the requested domain
//       is not available, temporarily or permanently
// - 400 which indicates the requested domain name is invalid or not permitted
func (m *Manager) HandleOCSPStapling(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/ocsp/")
	domain, err := idna.Lookup.ToASCII(domain)
	if err == nil {
		err = checkHostIsValid(context.Background(), domain)
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspHostNotPermitted)
		return
	}

	fingerprint := r.URL.Query().Get("fp")
	if fingerprint != "" && IsSelfSignedCertificate(fingerprint) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	response, nextUpdate, err := m.GetOCSPStaplingByName(domain, fingerprint)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var ttl = time.Until(nextUpdate)
	if ttl <= 0 {
		m.log.Warnf("got expired OCSP stapling: domain= %s", domain)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ttlSeconds := m.limitTTL(ttl)

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("X-Expire-At", fmt.Sprintf("%d", nextUpdate.Unix()))
	w.Header().Set("X-TTL", fmt.Sprintf("%d", ttlSeconds))
	w.Write(response)
}

func (m *Manager) GetOCSPStaplingByName(name string, fingerprint string) ([]byte, time.Time, error) {
	var keyName string
	// check managed domains first
	if certKey, ok := IsManagedDomain(name); ok {
		keyName = managedCertOCSPKeyName(certKey)
	} else
	// check wildcard domains
	if wcItem, ok := IsWildcardDomain(name); ok {
		keyName = wcItem.OCSPKeyName()
	} else
	// check concrete domains
	if err := m.autocert.HostPolicy(context.Background(), name); err == nil {
		keyName = m.OCSPKeyName(name)
	}
	if keyName == "" {
		return nil, time.Time{}, ErrStaplingNotCached
	}

	checkCacheCert := func() (*tls.Certificate, error) {
		return m.getCachedCertificateForOCSPStapling(name)
	}
	return m.ocspMgr.GetOCSPStapling(keyName, fingerprint, checkCacheCert)
}

func (m *Manager) limitTTL(ttl time.Duration) int {
	if ttl <= 30*time.Second {
		return 10
	}
	if ttl <= time.Minute {
		return 30
	}
	var ttlSeconds int64 = 3600
	if ttl < time.Hour {
		ttlSeconds = int64(ttl.Seconds() * 0.8)
	}
	// add a little randomness to the TTL
	var jitter int64 = 60
	if ttlSeconds <= 2*jitter {
		jitter = ttlSeconds / 2
	}
	n := rand63n(jitter)
	if n < ttlSeconds {
		ttlSeconds -= n
	}
	return int(ttlSeconds)
}
