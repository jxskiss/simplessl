package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var defaultSelfSignedOrganization = []string{"SSL Cert Server Self-Signed"}

var (
	selfSignedMu   sync.Mutex
	selfSignedCert atomic.Value // *tls.Certificate
)

func IsSelfSignedAllowed(domain string) bool {
	if !Cfg.SelfSigned.Enable {
		return false
	}
	if Cfg.SelfSigned.CheckSNI {
		if err := checkHostIsValid(context.Background(), domain); err != nil {
			return false
		}
	}
	return true
}

func GetSelfSignedCertificate() (*tls.Certificate, error) {
	if tlscert, ok := selfSignedCert.Load().(*tls.Certificate); ok {
		return tlscert, nil
	}

	selfSignedMu.Lock()
	defer selfSignedMu.Unlock()
	if tlscert, ok := selfSignedCert.Load().(*tls.Certificate); ok {
		return tlscert, nil
	}

	// check storage first
	store := Cfg.Storage.Cache
	ctx := context.Background()
	certPEM, err := store.Get(ctx, Cfg.SelfSigned.Cert)
	if err != nil && err != autocert.ErrCacheMiss {
		return nil, err
	}
	privKeyPEM, err := store.Get(ctx, Cfg.SelfSigned.PrivKey)
	if err != nil && err != autocert.ErrCacheMiss {
		return nil, err
	}
	if certPEM != nil && privKeyPEM != nil {
		tlscert, err := tls.X509KeyPair(certPEM, privKeyPEM)
		if err != nil {
			return nil, err
		}
		tlscert.Leaf, err = x509.ParseCertificate(tlscert.Certificate[0])
		if err != nil {
			return nil, err
		}
		selfSignedCert.Store(tlscert)
		return &tlscert, nil
	}

	// cache not available, create new certificate
	tlscert, err := createAndSaveSelfSignedCertificate()
	if err != nil {
		return nil, err
	}
	selfSignedCert.Store(tlscert)
	return tlscert, nil
}

func createAndSaveSelfSignedCertificate() (*tls.Certificate, error) {
	validDays := Cfg.SelfSigned.ValidDays
	organization := Cfg.SelfSigned.Organization
	certPEM, privKeyPEM, err := createSelfSignedCertificate(validDays, organization)
	if err != nil {
		return nil, err
	}

	store := Cfg.Storage.Cache
	ctx := context.Background()
	err = store.Put(ctx, Cfg.SelfSigned.Cert, certPEM)
	if err != nil {
		return nil, fmt.Errorf("self_signed: failed put certificate: %v", err)
	}
	err = store.Put(ctx, Cfg.SelfSigned.PrivKey, privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("self_signed: failed put private key: %v", err)
	}
	tlscert, _ := tls.X509KeyPair(certPEM, privKeyPEM)
	tlscert.Leaf, _ = x509.ParseCertificate(tlscert.Certificate[0])
	return &tlscert, nil
}

func createSelfSignedCertificate(validDays int, organization []string) (certPEM, privKeyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("self_singed: failed generate private key: %v", err)
		return
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = fmt.Errorf("self_signed: failed generate serial number: %v", err)
		return
	}

	var now = time.Now()
	var validDuration = time.Duration(validDays) * 24 * time.Hour

	certificate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: organization,
		},
		NotBefore: now,
		NotAfter:  now.Add(validDuration),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &privKey.PublicKey, privKey)
	if err != nil {
		err = fmt.Errorf("self_signed: failed create certificate: %v", err)
		return
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	privKeyBuf := &bytes.Buffer{}
	_ = EncodeECDSAKey(privKeyBuf, privKey)
	privKeyPEM = privKeyBuf.Bytes()
	return
}

/*
Sub command to generate self-signed certificate.
*/

const generateSelfSignedCertSubCommand = "generate-self-signed"

var generateSelfSignedCertFlagSet = flag.NewFlagSet(generateSelfSignedCertSubCommand, flag.ExitOnError)
var generateSelfSignedCertOptions = struct {
	validDays    int
	certOut      string
	keyOut       string
	organization StringArray
}{}

func init() {
	cmdFlags := generateSelfSignedCertFlagSet
	cmdFlags.IntVar(&generateSelfSignedCertOptions.validDays,
		"valid-days", 365, "number of days the cert is valid for")
	cmdFlags.StringVar(&generateSelfSignedCertOptions.certOut,
		"cert-out", "./self_signed.cert", "output certificate file")
	cmdFlags.StringVar(&generateSelfSignedCertOptions.keyOut,
		"key-out", "./self_signed.key", "output private key file")
	cmdFlags.Var(&generateSelfSignedCertOptions.organization,
		"organization", "certificate organization (may be given multiple times)")
}

func cmdGenerateSelfSignedCertificate() {
	generateSelfSignedCertFlagSet.Parse(os.Args[2:])
	opts := generateSelfSignedCertOptions
	if len(opts.organization) == 0 {
		opts.organization = defaultSelfSignedOrganization
	}

	certPEM, privKeyPEM, err := createSelfSignedCertificate(opts.validDays, opts.organization)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	err = ioutil.WriteFile(opts.certOut, certPEM, 0644)
	if err != nil {
		log.Fatalf("[FATAL] self_signed: failed write certificate file: %v", err)
	}
	err = ioutil.WriteFile(opts.keyOut, privKeyPEM, 0644)
	if err != nil {
		log.Fatalf("[FATAL] self_signed: failed write private keey file: %v", err)
	}
}
