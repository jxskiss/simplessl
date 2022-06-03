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
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
