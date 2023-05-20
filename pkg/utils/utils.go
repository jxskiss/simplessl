package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jxskiss/gopkg/v2/perf/fastrand"
)

func LoadLocalTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	var caPool *x509.CertPool
	if caFile != "" {
		var casCertPEM []byte
		casCertPEM, err = os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(casCertPEM) {
			return nil, fmt.Errorf("cannot load CA file: %v", caFile)
		}
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caPool,
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	return tlsConfig, nil
}

func ToPEMBlock(data interface{}) *pem.Block {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *x509.CertificateRequest:
		pemBlock = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.Raw}
	}
	return pemBlock
}

func EncodeRSAKey(w io.Writer, key *rsa.PrivateKey) error {
	b := x509.MarshalPKCS1PrivateKey(key)
	pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func EncodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}

func CalcCertFingerprint(leaf *x509.Certificate) string {
	checksum := sha1.Sum(leaf.Raw)
	fingerprint := hex.EncodeToString(checksum[:])
	return fingerprint
}

func ParseCertificate(data []byte) (tlscert *tls.Certificate, privPEM, pubPEM []byte, err error) {
	priv, pubPEM := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, nil, nil, errors.New("no private key found")
	}
	privPEM = pem.EncodeToMemory(priv)
	tlscertVal, err := tls.X509KeyPair(pubPEM, privPEM)
	if err != nil {
		return nil, nil, nil, err
	}
	tlscert = &tlscertVal

	now := time.Now()
	leaf, _ := x509.ParseCertificate(tlscert.Certificate[0])
	if now.Before(leaf.NotBefore) {
		return nil, nil, nil, errors.New("certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return nil, nil, nil, errors.New("certificate is expired")
	}
	tlscert.Leaf = leaf
	return tlscert, privPEM, pubPEM, nil
}

func ConcatPrivAndPubKey(privPEM, pubPEM []byte) []byte {
	out := privPEM
	if !bytes.HasSuffix(out, []byte{'\n'}) {
		out = append(out, '\n')
	}
	out = append(out, pubPEM...)
	return out
}

func WriteFile(name string, data []byte, perm os.FileMode) error {
	err := CreateNonExistingFolder(filepath.Dir(name), 0)
	if err != nil {
		return err
	}
	return os.WriteFile(name, data, perm)
}

func CreateNonExistingFolder(path string, perm os.FileMode) error {
	if perm == 0 {
		perm = 0o700
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, perm)
	} else if err != nil {
		return err
	}
	return nil
}

func LimitTTL(ttl time.Duration) int64 {
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}

	var result int64 = 3600
	if ttl < time.Hour {
		result = int64(ttl.Seconds() * 0.8)
	}

	// Add a little randomness to the TTL
	var jitter int64 = 60
	if result <= 2*jitter {
		jitter = result / 2
	}
	n := fastrand.Int63n(jitter)
	if n < result {
		result -= n
	}
	return result
}
