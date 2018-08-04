package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	mathrand "math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const VERSION = "0.2.0"

// StringArray implements flag.Value interface.
type StringArray []string

func (v *StringArray) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func (v *StringArray) String() string {
	return strings.Join(*v, ",")
}

// flags
var (
	domainList  StringArray
	patternList StringArray

	showVersion = flag.Bool("version", false, "print version string and quit")
	listen      = flag.String("listen", "127.0.0.1:8999", "listen address, be sure DON't open to the world")
	staging     = flag.Bool("staging", false, "use Let's Encrypt staging directory (default false)")
	cacheDir    = flag.String("cache-dir", "./secret-dir", "which directory to cache certificates")
	before      = flag.Int("before", 30, "renew certificates before how many days")
	email       = flag.String("email", "", "contact email, if Let's Encrypt client's key is already registered, this is not used")
	forceRSA    = flag.Bool("force-rsa", false, "generate certificates with 2048-bit RSA keys (default false)")
)

func main() {
	flag.Var(&domainList, "domain", "allowed domain names (may be given multiple times)")
	flag.Var(&patternList, "pattern", "allowed domain regex pattern using POSIX ERE (egrep) syntax, (may be given multiple times, ignored when domain parameters supplied)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ssl-cert-server v%s\n", VERSION)
		return
	}

	var hostPolicy autocert.HostPolicy
	if len(domainList) > 0 {
		hostPolicy = HostWhitelist(domainList...)
	} else if len(patternList) > 0 {
		patterns := make([]*regexp.Regexp, len(patternList))
		for i, p := range patternList {
			r := regexp.MustCompilePOSIX(p)
			patterns[i] = r
		}
		hostPolicy = RegexpWhitelist(patterns...)
	} else {
		// allow any domain by default
		hostPolicy = func(ctx context.Context, host string) error {
			return nil
		}
	}

	var directoryUrl string
	if *staging {
		directoryUrl = "https://acme-staging.api.letsencrypt.org/directory"
	} else {
		directoryUrl = acme.LetsEncryptURL
	}

	manager := &Manager{
		m: &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       autocert.DirCache(*cacheDir),
			RenewBefore: time.Duration(*before) * 24 * time.Hour,
			Client:      &acme.Client{DirectoryURL: directoryUrl},
			Email:       *email,
			HostPolicy:  hostPolicy,
		},
		ForceRSA: *forceRSA,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/cert/", manager.HandleCertificate)
	mux.HandleFunc("/ocsp/", manager.HandlerOCSPStapling)
	mux.Handle("/.well-known/acme-challenge/", manager.m.HTTPHandler(nil))

	log.Printf("listening on http://%v\n", *listen)
	err := http.ListenAndServe(*listen, mux)
	log.Println("server stopped:", err)
}

func (m *Manager) HandleCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/cert/")
	if err := checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid domain name."))
		return
	}
	cert, err := m.GetCertificateByName(domain)
	if err != nil {
		if err == ErrHostNotPermitted {
			log.Println("domain name not permitted:", domain)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Host name not permitted."))
		} else {
			log.Println("failed get certificate:", domain)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error getting certificate."))
		}
		return
	}

	var (
		now        = time.Now()
		ttl        = cert.Leaf.NotAfter.Sub(now)
		ttlSeconds int
	)
	if ttl <= 0 {
		log.Println("got expired certificate:", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if ttl > 3600*time.Second {
		ttlSeconds = 3600
	} else {
		ttlSeconds = int(ttl.Seconds() * 0.8)
	}
	// add a little randomness to the TTL
	n := mathrand.Intn(100)
	if n < ttlSeconds {
		ttlSeconds -= n
	}

	var (
		certBuf    bytes.Buffer
		privKeyBuf bytes.Buffer
	)
	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&certBuf, pb); err != nil {
			log.Println("failed encode certificate:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if err := EncodeRSAKey(&privKeyBuf, key); err != nil {
			log.Println("failed encode rsa key:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case *ecdsa.PrivateKey:
		if err := EncodeECDSAKey(&privKeyBuf, key); err != nil {
			log.Println("failed encode ecdsa key:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		log.Printf("unknown private key type: %T\n", key)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(struct {
		Cert     string `json:"cert"`
		PKey     string `json:"pkey"`
		ExpireAt int64  `json:"expire_at"` // seconds since epoch
		TTL      int    `json:"ttl"`       // in seconds
	}{
		string(certBuf.Bytes()),
		string(privKeyBuf.Bytes()),
		cert.Leaf.NotAfter.Unix(),
		ttlSeconds,
	})

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (m *Manager) HandlerOCSPStapling(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/ocsp/")
	if err := checkDomainName(domain); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid domain name."))
		return
	}
	response, nextUpdate, err := m.GetOCSPStapling(domain)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			w.WriteHeader(http.StatusNotFound)
		} else {
			log.Println("failed get OCSP stapling:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	var (
		now        = time.Now()
		ttl        = nextUpdate.Sub(now)
		ttlSeconds int
	)
	if ttl <= 0 {
		log.Println("got expired OCSP stapling:", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if ttl > 3600*time.Second {
		ttlSeconds = 3600
	} else {
		ttlSeconds = int(ttl.Seconds() * 0.8)
	}
	// add a little randomness to the TTL
	n := mathrand.Intn(100)
	if n < ttlSeconds {
		ttlSeconds -= n
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("X-Expire-At", fmt.Sprintf("%d", nextUpdate.Unix()))
	w.Header().Set("X-TTL", fmt.Sprintf("%d", ttlSeconds))
	w.Write(response)
}

func checkDomainName(name string) error {
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
