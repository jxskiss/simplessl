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
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const VERSION = "0.2.0"

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
	listen      = flag.String("listen", "127.0.0.1:8999", "listen address, be sure DON'T open to the world")
	staging     = flag.Bool("staging", false, "use Let's Encrypt staging directory (default false)")
	cacheDir    = flag.String("cache-dir", "./secret-dir", "which directory to cache certificates")
	before      = flag.Int("before", 30, "renew certificates before how many days")
	email       = flag.String("email", "", "contact email, if Let's Encrypt client's key is already registered, this is not used")
	forceRSA    = flag.Bool("force-rsa", false, "generate certificates with 2048-bit RSA keys (default false)")
)

func main() {
	flag.Var(&domainList, "domain", "allowed domain names (may be given multiple times)")
	flag.Var(&patternList, "pattern", "allowed domain regex pattern using POSIX ERE (egrep) syntax, (may be given multiple times, will be ignored when domain parameters supplied)")
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
	go manager.listenCertChanges()

	mux := http.NewServeMux()
	mux.Handle("/cert/", loggingMiddleware(http.HandlerFunc(manager.HandleCertificate)))
	mux.Handle("/ocsp/", loggingMiddleware(http.HandlerFunc(manager.HandleOCSPStapling)))
	mux.Handle("/.well-known/acme-challenge/", loggingMiddleware(manager.m.HTTPHandler(nil)))
	server := http.Server{Addr: *listen, Handler: mux}
	go func() {
		log.Printf("[INFO] server: listening on http://%v\n", *listen)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalln("[FATAL] server: stopped unexpectly: err=", err)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(ctx)
	log.Println("[INFO] server: shutdown gracefully")
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

var accessLogger = log.New(os.Stdout, "", 0)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(hdlr http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		lrw := &loggingResponseWriter{w, http.StatusOK}
		defer func(start time.Time) {
			// [yyyymmdd hhmmss Addr] Status Method URI Duration
			const LogFormat = "[%s %s] %d %s %s %s\n"
			now := time.Now().UTC()
			logTime := now.Format("20060102 15:04:05")
			accessLogger.Printf(LogFormat, logTime, req.RemoteAddr, lrw.statusCode, req.Method, req.RequestURI, now.Sub(start))
		}(time.Now())
		hdlr.ServeHTTP(lrw, req)
	})
}
