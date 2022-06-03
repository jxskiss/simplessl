package lego

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

type Certificate struct {
	RootDomain string
	Domains    []string

	CertPEM     []byte
	KeyPEM      []byte
	Certificate *tls.Certificate
}

func (cert *Certificate) GetFilenames() (certName, keyName string) {
	domain := sanitizedDomain(cert.Domains[0])
	certName = filepath.Join("certificates", domain+".crt")
	keyName = filepath.Join("certificates", domain+".key")
	return
}

func (cert *Certificate) Load(rootPath string) error {
	certName, keyName := cert.GetFilenames()
	certFile := filepath.Join(rootPath, certName)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("cannot read certificate file: %w", err)
	}
	keyFile := filepath.Join(rootPath, keyName)
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}
	certBytes := utils.ConcatPrivAndPubKey(keyPEM, certPEM)
	tlscert, _, _, err := utils.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("cannot parse certificate: %w", err)
	}
	cert.CertPEM = certPEM
	cert.KeyPEM = keyPEM
	cert.Certificate = tlscert
	return nil
}

func (cert *Certificate) Save(rootPath string) error {
	certName, keyName := cert.GetFilenames()
	certFile := filepath.Join(rootPath, certName)
	err := writeFile(certFile, cert.CertPEM, 0600)
	if err != nil {
		return fmt.Errorf("cannot write certificate file: %w", err)
	}
	keyFile := filepath.Join(rootPath, keyName)
	err = writeFile(keyFile, cert.KeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("cannot write key file: %w", err)
	}
	return nil
}
