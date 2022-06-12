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

func (p *Server) BuildRoutes(mux *http.ServeMux) {
	accessLogger := zlog.Named("access").Sugar()
	var _mw = func(h http.Handler) http.Handler {
		return loggingMiddleware(accessLogger, recoverMiddleware(p.log, h))
	}
	mux.Handle("/cert/", _mw(http.HandlerFunc(p.HandleCertificate)))
	mux.Handle("/ocsp/", _mw(http.HandlerFunc(p.HandleOCSPStapling)))
	mux.Handle("/.well-known/acme-challenge/", _mw(p.autocert.autocert.HTTPHandler(nil)))
}

// HandleCertificate handlers requests of SSL certificate.
//
// Possible responses are:
// - 200 with the certificate data as response
// - 400 the requested domain name is invalid or not permitted
// - 500 which indicates the server failed to process the request,
//       in such case, the body will be filled with the error message
func (p *Server) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	domain, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		p.log.Infof("got invalid domain name: err= %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}

	var tlscert *tls.Certificate
	var certType int
	var isALPN01 = r.URL.Query().Get("alpn") == "1"
	if isALPN01 {
		certType = ALPNCert
		tlscert, err = p.autocert.GetAutocertALPN01Certificate(domain)
	} else {
		tlscert, certType, err = p.GetCertificateByName(domain)
	}
	if err != nil {
		if err == ErrHostNotPermitted {
			p.log.Infof("domain name not permitted: domain= %s", domain)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(RspHostNotPermitted)
		} else {
			p.log.Errorf("failed get certificate: domain= %s err= %v", domain, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrGetCertificate)
		}
		return
	}

	var ttlSeconds int
	if !isALPN01 {
		var ttl = time.Until(tlscert.Leaf.NotAfter)
		if ttl <= 0 {
			p.log.Warnf("got expired certificate: domain= %s", domain)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspCertificateIsExpired)
			return
		}
		ttlSeconds = limitTTL(ttl)
	}
	response, err := p.marshalCertificate(tlscert, certType, ttlSeconds)
	if err != nil {
		p.log.Errorf("failed marshal certificate: domain= %s err= %v", domain, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(RspErrMarshalCertificate)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (p *Server) marshalCertificate(cert *tls.Certificate, certType int, ttl int) ([]byte, error) {
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

func (p *Server) GetCertificateByName(name string) (tlscert *tls.Certificate, certType int, err error) {
	cfg := p.cfg
	// check managed domains first
	if certKey, ok := cfg.IsManagedDomain(name); ok {
		certType = Managed
		tlscert, err = p.managed.Get(certKey)
	} else
	// check wildcard domains
	if wcItem, ok := cfg.IsWildcardDomain(name); ok {
		certType = Wildcard
		tlscert, err = p.wildcard.Get(wcItem, true)
	} else
	// check concrete domains
	if err = cfg.LetsEncrypt.HostPolicy(context.Background(), name); err == nil {
		certType = LetsEncrypt
		tlscert, err = p.autocert.GetAutocertCertificate(name)
	} else
	// check self-signed
	if cfg.IsSelfSignedAllowed(name) {
		certType = SelfSigned
		tlscert, err = p.GetSelfSignedCertificate()
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
func (p *Server) HandleOCSPStapling(w http.ResponseWriter, r *http.Request) {
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

	response, nextUpdate, err := p.GetOCSPStaplingByName(domain, fingerprint)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var ttl = time.Until(nextUpdate)
	if ttl <= 0 {
		p.log.Warnf("got expired OCSP stapling: domain= %s", domain)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ttlSeconds := limitTTL(ttl)

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("X-Expire-At", fmt.Sprintf("%d", nextUpdate.Unix()))
	w.Header().Set("X-TTL", fmt.Sprintf("%d", ttlSeconds))
	w.Write(response)
}

func (p *Server) GetOCSPStaplingByName(name string, fingerprint string) ([]byte, time.Time, error) {
	cfg := p.cfg
	var keyName string
	// check managed domains first
	if certKey, ok := cfg.IsManagedDomain(name); ok {
		keyName = p.managed.OCSPKeyName(certKey)
	} else
	// check wildcard domains
	if wcItem, ok := cfg.IsWildcardDomain(name); ok {
		keyName = wcItem.OCSPKeyName()
	} else
	// check concrete domains
	if err := cfg.LetsEncrypt.HostPolicy(context.Background(), name); err == nil {
		keyName = p.autocert.OCSPKeyName(name)
	}
	if keyName == "" {
		return nil, time.Time{}, ErrStaplingNotCached
	}

	checkCacheCert := func() (*tls.Certificate, error) {
		return p.getCachedCertificateForOCSPStapling(name, fingerprint)
	}
	return p.ocspMgr.GetOCSPStapling(keyName, fingerprint, checkCacheCert)
}
