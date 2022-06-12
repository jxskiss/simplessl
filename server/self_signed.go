package server

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
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

var (
	selfSignedMu          sync.Mutex
	selfSignedCert        atomic.Value // *tls.Certificate
	selfSignedFingerprint atomic.Value // string
)

func IsSelfSignedCertificate(fingerprint string) bool {
	fp, _ := selfSignedFingerprint.Load().(string)
	return fingerprint == fp
}

func (p *Server) GetSelfSignedCertificate() (*tls.Certificate, error) {
	if tlscert, ok := selfSignedCert.Load().(*tls.Certificate); ok {
		return tlscert, nil
	}

	selfSignedMu.Lock()
	defer selfSignedMu.Unlock()
	if tlscert, ok := selfSignedCert.Load().(*tls.Certificate); ok {
		return tlscert, nil
	}

	// check storage first
	certKey := p.cfg.SelfSigned.CertKey
	tlscert, _, _, err := p.stor.LoadCertificateFromStore(certKey)
	if err != nil && err != ErrCacheMiss {
		return nil, fmt.Errorf("self_signed: %v", err)
	}
	if tlscert != nil {
		fingerprint := utils.CalcCertFingerprint(tlscert.Leaf)
		selfSignedCert.Store(tlscert)
		selfSignedFingerprint.Store(fingerprint)
		return tlscert, nil
	}

	// cache not available, create new certificate
	tlscert, err = p.createAndSaveSelfSignedCertificate()
	if err != nil {
		return nil, err
	}
	fingerprint := utils.CalcCertFingerprint(tlscert.Leaf)
	selfSignedCert.Store(tlscert)
	selfSignedFingerprint.Store(fingerprint)
	return tlscert, nil
}

func (p *Server) createAndSaveSelfSignedCertificate() (*tls.Certificate, error) {
	cfg := p.cfg
	validDays := cfg.SelfSigned.ValidDays
	organization := cfg.SelfSigned.Organization
	certPEM, privKeyPEM, err := CreateSelfSignedCertificate(validDays, organization)
	if err != nil {
		return nil, err
	}

	cacheData := append(privKeyPEM, certPEM...)
	err = cfg.Storage.Cache.Put(context.Background(), cfg.SelfSigned.CertKey, cacheData)
	if err != nil {
		return nil, fmt.Errorf("self_signed: failed put certificate: %v", err)
	}
	tlscert, _, _, _ := utils.ParseCertificate(cacheData)
	return tlscert, nil
}

func CreateSelfSignedCertificate(validDays int, organization []string) (certPEM, privKeyPEM []byte, err error) {
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
	_ = utils.EncodeECDSAKey(privKeyBuf, privKey)
	privKeyPEM = privKeyBuf.Bytes()
	return
}
