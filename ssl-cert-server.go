package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"flag"
	"net/http"

	"github.com/gocraft/web"
	"github.com/golang/glog"
	"github.com/jxskiss/ssl-cert-server/autocert"
	"golang.org/x/crypto/acme"
)

var staging = flag.Bool("staging", false, "use Let's Encrypt staging directory")
var forceRSA = flag.Bool("force-rsa", false, "generate certificates with 2048-bit RSA keys")
var listen = flag.String("listen", "127.0.0.1:8999", "listen address, be sure DON't open to the world")
var manager autocert.Manager

func init() {
	flag.Parse()
	glog.Flush()

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
	}{string(certBuf.Bytes()), string(privKeyBuf.Bytes()), 3600})

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

func (c *Context) OCSPStaplingHandler(w web.ResponseWriter, r *web.Request) {
	domain := r.PathParams["domain"]
	response, err := manager.GetOCSPStapling(domain)
	if err != nil {
		glog.Errorf("ocsp stapling: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// TODO: add "Expires" and "Cache" headers
	w.Header().Set("Content-Type", "application/ocsp-response")
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

func main() {
	router := web.New(Context{}).
		Middleware(web.LoggerMiddleware).
		Get("/cert/:domain:[^.]+\\..+", (*Context).CertHandler).
		Get("/ocsp/:domain:[^.]+\\..+", (*Context).OCSPStaplingHandler).
		Get("/.well-known/acme-challenge/:token", (*Context).ChallengeHandler)
	glog.Fatal(http.ListenAndServe(*listen, router))
}
