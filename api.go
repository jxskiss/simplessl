package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	RspInvalidDomainName    = []byte("Invalid domain name.")
	RspHostNotPermitted     = []byte("Host name not permitted.")
	RspNoValidCertificate   = []byte("No valid certificate available.")
	RspNoValidOCSPStapling  = []byte("No valid OCSP stapling available.")
	RspDomainNotCached      = []byte("Domain certificate not cached.")
	RspErrGetCertificate    = []byte("Error getting certificate.")
	RspErrEncodeCertificate = []byte("Error encode certificate.")
	RspErrGetOCSPStapling   = []byte("Error get OCSP stapling.")
)

func buildRoutes(mux *http.ServeMux, manager *Manager) {
	mux.Handle("/cert/", loggingMiddleware(http.HandlerFunc(manager.HandleCertificate)))
	mux.Handle("/ocsp/", loggingMiddleware(http.HandlerFunc(manager.HandleOCSPStapling)))
	mux.Handle("/.well-known/acme-challenge/", loggingMiddleware(manager.m.HTTPHandler(nil)))
}

func (m *Manager) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	if err := m.checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}
	cert, err := m.GetCertificateByName(domain)
	if err != nil {
		if err == ErrHostNotPermitted {
			log.Println("[WARN] manager: domain name not permitted: domain=", domain)
			w.WriteHeader(http.StatusForbidden)
			w.Write(RspHostNotPermitted)
		} else {
			log.Println("[ERROR] manager: failed get certificate: domain=", domain, "err=", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrGetCertificate)
		}
		return
	}

	var ttl = time.Until(cert.Leaf.NotAfter)
	if ttl <= 0 {
		log.Println("[WARN] manager: got expired certificate: domain=", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(RspNoValidCertificate)
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
			log.Println("[ERROR] manager: failed encode certificate: domain=", domain, "err=", err)
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
		log.Printf("[ERROR] manager: failed encode private key: domain= %v type= %T err= %v\n", domain, cert.PrivateKey, err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(RspErrEncodeCertificate)
		return
	}

	response, _ := json.Marshal(struct {
		Cert     string `json:"cert"`
		PKey     string `json:"pkey"`
		ExpireAt int64  `json:"expire_at"` // seconds since epoch
		TTL      int    `json:"ttl"`       // in seconds
	}{
		string(certBuf.Bytes()),
		string(privKeyBuf.Bytes()),
		cert.Leaf.NotAfter.Unix(),
		ttlSeconds,
	}) // error ignored, shall not fail

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (m *Manager) HandleOCSPStapling(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/ocsp/")
	if err := m.checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(RspInvalidDomainName)
		return
	}
	response, nextUpdate, err := m.GetOCSPStapling(domain)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			w.WriteHeader(http.StatusNotFound)
			w.Write(RspDomainNotCached)
		} else {
			log.Println("[ERROR] manager: failed get OCSP stapling: domain=", domain, "err=", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(RspErrGetOCSPStapling)
		}
		return
	}

	var ttl = time.Until(nextUpdate)
	if ttl <= 0 {
		log.Println("[WARN] manager: got expired OCSP stapling: domain=", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(RspNoValidOCSPStapling)
		return
	}
	ttlSeconds := m.limitTTL(ttl)

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("X-Expire-At", fmt.Sprintf("%d", nextUpdate.Unix()))
	w.Header().Set("X-TTL", fmt.Sprintf("%d", ttlSeconds))
	w.Write(response)
}

func (m Manager) limitTTL(ttl time.Duration) int {
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

func (m Manager) checkDomainName(name string) error {
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
