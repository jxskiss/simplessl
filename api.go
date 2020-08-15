package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// certificate types
const (
	LetsEncrypt = 0
	Managed     = 1
	SelfSigned  = 100
)

var (
	RspInvalidDomainName    = []byte("Invalid domain name.")
	RspHostNotPermitted     = []byte("Host name not permitted.")
	RspCertificateIsExpired = []byte("Certificate is expired.")
	RspErrGetCertificate    = []byte("Error getting certificate.")
	RspErrEncodeCertificate = []byte("Error encode certificate.")
)

func buildRoutes(mux *http.ServeMux, manager *Manager) {
	var _mw = func(h http.Handler) http.Handler {
		return loggingMiddleware(recoverMiddleware(h))
	}
	mux.Handle("/cert/", _mw(http.HandlerFunc(manager.HandleCertificate)))
	mux.Handle("/ocsp/", _mw(http.HandlerFunc(manager.HandleOCSPStapling)))
	mux.Handle("/.well-known/acme-challenge/", _mw(manager.m.HTTPHandler(nil)))
}

// HandlerCertificate handlers requests of SSL certificate.
//
// Possible responses are:
// - 200 with the certificate data as response
// - 400 which indicates there is error in the client request,
//       in such case, the body will be filled with the error message
// - 403 the requested domain name is not permitted
// - 500 which indicates the server failed to process the request,
//       in such case, the body will be filled with the error message
func (m *Manager) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	if err := m.checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}
	cert, certType, err := m.GetCertificateByName(domain)
	if err != nil {
		if err == ErrHostNotPermitted {
			log.Printf("[WARN] manager: domain name not permitted: domain= %s", domain)
			w.WriteHeader(http.StatusForbidden)
			w.Write(RspHostNotPermitted)
		} else {
			log.Printf("[ERROR] manager: failed get certificate: domain= %s err= %v", domain, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrGetCertificate)
		}
		return
	}

	var ttl = time.Until(cert.Leaf.NotAfter)
	if ttl <= 0 {
		log.Printf("[WARN] manager: got expired certificate: domain= %s", domain)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(RspCertificateIsExpired)
		return
	}
	ttlSeconds := m.limitTTL(ttl)

	var (
		certBuf    bytes.Buffer
		privKeyBuf bytes.Buffer
	)
	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err = pem.Encode(&certBuf, pb); err != nil {
			log.Printf("[ERROR] manager: failed encode certificate: domain= %s err= %v", domain, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrEncodeCertificate)
			return
		}
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = EncodeRSAKey(&privKeyBuf, key)
	case *ecdsa.PrivateKey:
		err = EncodeECDSAKey(&privKeyBuf, key)
	default:
		err = fmt.Errorf("unknown private key type")
	}
	if err != nil {
		log.Printf("[ERROR] manager: failed encode private key: domain= %v type= %T err= %v", domain, cert.PrivateKey, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(RspErrEncodeCertificate)
		return
	}

	fingerprint := sha1.Sum(cert.Leaf.Raw)
	response, _ := json.Marshal(struct {
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
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		ExpireAt:    cert.Leaf.NotAfter.Unix(),
		TTL:         ttlSeconds,
	}) // error ignored, shall not fail

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (m *Manager) GetCertificateByName(name string) (tlscert *tls.Certificate, certType int, err error) {
	// check managed domains first
	if cert, privKey, ok := IsManagedDomain(name); ok {
		certType = Managed
		tlscert, err = GetManagedCertificate(cert, privKey)
	} else
	// check auto issued certificates from Let's Encrypt
	if err := m.m.HostPolicy(context.Background(), name); err == nil {
		certType = LetsEncrypt
		tlscert, err = m.GetCertificate(name)
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
// - 400 which indicates there is error in the client request,
//       in such case, the body will be filled with the error message
func (m *Manager) HandleOCSPStapling(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/ocsp/")
	if err := m.checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}
	fingerprint := r.URL.Query().Get("fp")
	response, nextUpdate, err := m.GetOCSPStaplingByName(domain, fingerprint)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var ttl = time.Until(nextUpdate)
	if ttl <= 0 {
		log.Printf("[WARN] manager: got expired OCSP stapling: domain= %s", domain)
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
	if cert, privKey, ok := IsManagedDomain(name); ok {
		keyName = managedCertOCSPKeyName(cert, privKey)
	} else
	// check auto issued certificates from Let's Encrypt
	if err := m.m.HostPolicy(context.Background(), name); err == nil {
		keyName = m.OCSPKeyName(name)
	}
	if keyName == "" {
		return nil, time.Time{}, ErrStaplingNotCached
	}
	return OCSPManager.GetOCSPStapling(keyName, fingerprint)
}

func (m *Manager) limitTTL(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
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
	n := pseudoRand.int63n(jitter)
	if n < ttlSeconds {
		ttlSeconds -= n
	}
	return int(ttlSeconds)
}

func (m *Manager) checkDomainName(name string) error {
	if name == "" {
		return errors.New("missing domain name")
	}
	if !strings.Contains(strings.Trim(name, "."), ".") {
		return errors.New("domain name component invalid")
	}
	if strings.ContainsAny(name, `/\`) {
		return errors.New("domain name contains invalid character")
	}
	return nil
}
