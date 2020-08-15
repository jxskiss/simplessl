package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

func NewDirCache(cacheDir string) (autocert.Cache, error) {
	return autocert.DirCache(cacheDir), nil
}

// loadCertificateFromStore loads certificate from storage, if the certificate
// exists and is valid, it will be returned, or an error otherwise.
func loadCertificateFromStore(certKey string) (*tls.Certificate, error) {
	ctx := context.Background()
	data, err := Cfg.Storage.Cache.Get(ctx, certKey)
	if err != nil {
		return nil, err
	}
	return parseCertificate(data)
}

func parseCertificate(data []byte) (*tls.Certificate, error) {
	priv, pubPEM := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, errors.New("no private key found")
	}
	privPEM := pem.EncodeToMemory(priv)
	tlscert, err := tls.X509KeyPair(pubPEM, privPEM)
	if err != nil {
		return nil, err
	}

	now := timeNow()
	leaf, _ := x509.ParseCertificate(tlscert.Certificate[0])
	if now.Before(leaf.NotBefore) {
		return nil, errors.New("certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return nil, errors.New("certificate is expired")
	}
	tlscert.Leaf = leaf
	return &tlscert, nil
}
