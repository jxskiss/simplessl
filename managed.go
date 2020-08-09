package main

import (
	"context"
	"crypto/tls"
	"fmt"
)

func (m *Manager) IsManagedDomain(domain string) (cert, privKey string, ok bool) {
	for _, x := range Cfg.Managed {
		if x.Regex.MatchString(domain) {
			return x.Cert, x.PrivKey, true
		}
	}
	return "", "", false
}

func (m *Manager) GetManagedCertificate(cert, privKey string) (*tls.Certificate, error) {
	store := Cfg.Storage.Cache
	ctx := context.Background()
	certPEM, err := store.Get(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("managed: failed get certificate bytes")
	}
	privKeyPEM, err := store.Get(ctx, privKey)
	if err != nil {
		return nil, fmt.Errorf("managed: failed get private key bytes")
	}
	tlscert, err := tls.X509KeyPair(certPEM, privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("managed: failed parse public/private key pair")
	}
	return &tlscert, nil
}
