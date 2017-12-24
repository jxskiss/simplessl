package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gocraft/web"
	"github.com/jxskiss/glog"
	"github.com/jxskiss/ssl-cert-server/autocert"
	"golang.org/x/crypto/acme"
)

var (
	staging  = flag.Bool("staging", false, "use Let's Encrypt staging directory")
	forceRSA = flag.Bool("force-rsa", false, "generate certificates with 2048-bit RSA keys")
	listen   = flag.String("listen", "127.0.0.1:8999", "listen address, be sure DON't open to the world")
	manager  autocert.Manager
)

func init() {
	flag.Parse()

	var directoryUrl string
	if *staging {
		directoryUrl = "https://acme-staging.api.letsencrypt.org/directory"
	} else {
		directoryUrl = acme.LetsEncryptURL
	}

	manager = autocert.Manager{
		Cache:    autocert.DirCache("secret-dir"),
		Prompt:   autocert.AcceptTOS,
		Client:   &acme.Client{DirectoryURL: directoryUrl},
		ForceRSA: *forceRSA,
	}
}

type Context struct{}

func (c *Context) CertHandler(w web.ResponseWriter, r *web.Request) {
	domain := r.PathParams["domain"]
	cert, err := manager.GetCertificateByName(domain)
	if err != nil {
		glog.Errorf("failed getting cert: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var (
		now        = time.Now()
		ttl        = cert.Leaf.NotAfter.Sub(now)
		ttlSeconds int
	)
	if ttl <= 0 {
		glog.Errorf("expired certificate for domain: %s", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if ttl > 3600*time.Second {
		ttlSeconds = 3600
	} else {
		ttlSeconds = int(ttl.Seconds() * 0.8)
	}

	var (
		certBuf    bytes.Buffer
		privKeyBuf bytes.Buffer
	)
	for _, b := range cert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&certBuf, pb); err != nil {
			glog.Errorf("encoding certificate: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	switch key := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if err := autocert.EncodeRSAKey(&privKeyBuf, key); err != nil {
			glog.Errorf("encoding rsa private key: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case *ecdsa.PrivateKey:
		if err := autocert.EncodeECDSAKey(&privKeyBuf, key); err != nil {
			glog.Errorf("encoding ecdsa key: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	default:
		glog.Errorf("unknown private key type")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(struct {
		Cert string `json:"cert"`
		PKey string `json:"pkey"`
		TTL  int    `json:"ttl"` // in seconds
	}{string(certBuf.Bytes()), string(privKeyBuf.Bytes()), ttlSeconds})

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (c *Context) OCSPStaplingHandler(w web.ResponseWriter, r *web.Request) {
	domain := r.PathParams["domain"]
	response, nextUpdate, err := manager.GetOCSPStapling(domain)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			w.WriteHeader(http.StatusNotFound)
		} else {
			glog.Errorf("ocsp stapling: %s", err)
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
		glog.Errorf("expired OCSP stapling for domain: %s", domain)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if ttl > 3600*time.Second {
		ttlSeconds = 3600
	} else {
		ttlSeconds = int(ttl.Seconds() * 0.8)
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d,public,no-transform,must-revalidate", ttlSeconds))
	w.Write(response)
}

func (c *Context) ChallengeHandler(w web.ResponseWriter, r *web.Request) {
	token := r.PathParams["token"]
	response, err := manager.GetHTTP01ChallengeResponse(token)
	if err != nil {
		if err == autocert.ChallengeNotFount {
			glog.Warningf("token not found: %s", token)
			w.WriteHeader(http.StatusNotFound)
		} else {
			glog.Errorf("challenge error: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	w.Write([]byte(response))
}

var stdout = log.New(os.Stdout, "", 0)

func accessLoggerMiddleware(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {
	startTime := time.Now()

	next(rw, req)

	// Ammdd hhmmss Addr] Status Method URI Duration
	const LogFormat = "A%s %s] %d %s %s %s\n"

	duration := time.Since(startTime).Nanoseconds()
	var durationUnits string
	switch {
	case duration > 2000000:
		durationUnits = "ms"
		duration /= 1000000
	case duration > 1000:
		durationUnits = "μs"
		duration /= 1000
	default:
		durationUnits = "ns"
	}
	durationFormatted := fmt.Sprintf("%d%s", duration, durationUnits)

	logTime := time.Now().Format("0102 150405")
	stdout.Printf(LogFormat, logTime, req.RemoteAddr, rw.StatusCode(),
		req.Method, req.RequestURI, durationFormatted)
}

func main() {
	defer glog.Flush()

	router := web.New(Context{}).
		Middleware(accessLoggerMiddleware).
		Get("/cert/:domain:[^.]+\\..+", (*Context).CertHandler).
		Get("/ocsp/:domain:[^.]+\\..+", (*Context).OCSPStaplingHandler).
		Get("/.well-known/acme-challenge/:token", (*Context).ChallengeHandler)

	glog.Infof("Listening on http://%s", *listen)
	glog.Fatal(http.ListenAndServe(*listen, router))
}
