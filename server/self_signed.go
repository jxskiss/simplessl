package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"

	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/pb"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

const SelfSignedCertKey = "self_signed"

type SelfSignedManager interface {
	IsSelfSigned(fp string) bool
	GetCertificate(ctx context.Context) (*tls.Certificate, error)
}

func NewSelfSignedManager(cfg *config.Config, storage StorageManager) SelfSignedManager {
	return &selfSignedImpl{
		cfg:  cfg,
		stor: storage,
		log:  zlog.Named("selfSigned").Sugar(),
	}
}

type selfSignedImpl struct {
	sync.RWMutex
	cert *tls.Certificate
	fp   string

	cfg  *config.Config
	stor StorageManager
	log  *zap.SugaredLogger
}

func (p *selfSignedImpl) IsSelfSigned(fp string) bool {
	p.RLock()
	if p.fp != "" {
		defer p.RUnlock()
		return fp == p.fp
	}

	p.RUnlock()
	_, fp, _ = p._getCertificate(context.Background())
	return fp == p.fp
}

func (p *selfSignedImpl) GetCertificate(ctx context.Context) (*tls.Certificate, error) {
	cert, _, err := p._getCertificate(ctx)
	return cert, err
}

func (p *selfSignedImpl) _getCertificate(ctx context.Context) (cert *tls.Certificate, fp string, err error) {
	p.Lock()
	defer p.Unlock()
	if p.cert != nil {
		return p.cert, p.fp, nil
	}

	// check storage first
	cert, _, _, err = p.stor.LoadCertificate(ctx, pb.Certificate_SELF_SIGNED, SelfSignedCertKey)
	if err != nil && err != ErrCacheMiss {
		return nil, "", fmt.Errorf("selfSigned: %w", err)
	}
	if cert != nil {
		p.log.Infof("load certificate from storage, notAfter= %v", cert.Leaf.NotAfter)
		p.cert = cert
		p.fp = utils.CalcCertFingerprint(cert.Leaf)
		return p.cert, p.fp, nil
	}

	// cache not available, create new certificate
	cert, err = p.createAndSaveCertificate(ctx)
	if err != nil {
		return nil, "", err
	}
	p.cert = cert
	p.fp = utils.CalcCertFingerprint(cert.Leaf)
	return p.cert, p.fp, nil
}

func (p *selfSignedImpl) createAndSaveCertificate(ctx context.Context) (*tls.Certificate, error) {
	validDays := p.cfg.SelfSigned.ValidDays
	organization := p.cfg.SelfSigned.Organization
	pubKey, privKey, err := CreateSelfSignedCertificate(&GenCertArgs{
		ValidDays:     validDays,
		Organizations: []string{organization},
		Type:          "ca",
	})
	if err != nil {
		return nil, err
	}

	p.log.Infof("saving new self-signed certificate")
	err = p.stor.SaveCertificate(ctx, pb.Certificate_SELF_SIGNED, SelfSignedCertKey, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("selfSigned: save certificate: %w", err)
	}
	certBuf := append(privKey, pubKey...)
	cert, _, _, err := utils.ParseCertificate(certBuf)
	if err != nil {
		return nil, fmt.Errorf("selfSigned: parse certificate: %w", err)
	}
	return cert, nil
}

type GenCertArgs struct {
	CA            *tls.Certificate
	ValidDays     int
	Organizations []string
	Hosts         []string
	Type          string // "ca" | "cert" | "server"
}

func CreateSelfSignedCertificate(args *GenCertArgs) (pubKeyPEM, privKeyPEM []byte, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("selfSigned: generate private key: %w", err)
		return
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		err = fmt.Errorf("selfSigned: generate serial number: %w", err)
		return
	}

	var now = time.Now()
	var validDuration = time.Duration(args.ValidDays) * 24 * time.Hour

	var caCert *x509.Certificate
	var caPrivKey crypto.PrivateKey

	certificate := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    now,
		NotAfter:     now.Add(validDuration),
	}
	if len(args.Organizations) > 0 {
		certificate.Subject = pkix.Name{
			Organization: args.Organizations,
		}
	}
	if len(args.Hosts) > 0 {
		certificate.DNSNames = args.Hosts
	}
	switch args.Type {
	case "ca":
		certificate.BasicConstraintsValid = true
		certificate.IsCA = true
		certificate.KeyUsage = x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
		caCert = certificate
		caPrivKey = privKey
	case "client":
		certificate.KeyUsage = x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		}
		caCert = args.CA.Leaf
		caPrivKey = args.CA.PrivateKey
	case "server":
		certificate.KeyUsage = x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment
		certificate.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		}
		caCert = args.CA.Leaf
		caPrivKey = args.CA.PrivateKey
	default:
		err = fmt.Errorf("unknown args.Type to generate certificate: %v", args.Type)
		return
	}

	return generateCertificate(caCert, caPrivKey, certificate, privKey)
}

func generateCertificate(
	caCert *x509.Certificate, caPrivKey crypto.PrivateKey,
	tmpl *x509.Certificate, privKey *ecdsa.PrivateKey,
) (pubKeyPEM, privKeyPEM []byte, err error) {

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pub := privKey.Public()
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	h := sha1.New()
	h.Write(pkixpub)
	tmpl.SubjectKeyId = h.Sum(nil)

	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		err = fmt.Errorf("selfSigned: create certificate: %w", err)
		return
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	privKeyBuf := &bytes.Buffer{}
	_ = utils.EncodeECDSAKey(privKeyBuf, privKey)
	privKeyPEM = privKeyBuf.Bytes()
	return
}
