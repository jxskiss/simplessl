package server

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

var acmeHTTPClient *http.Client

func init() {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	acmeHTTPClient = &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
}

func (p *acmeImpl) newACMEClient(ctx context.Context, certName string) (account acme.Account, client *acmez.Client, err error) {
	acc, cert, err := p.cfg.GetACMEConfig(certName)
	if err != nil {
		return account, nil, err
	}
	privKey, err := p.getAccountPrivateKey(ctx, acc)
	if err != nil {
		return account, nil, err
	}
	account = acme.Account{
		Contact:              formatContact(acc.Email),
		TermsOfServiceAgreed: true,
		PrivateKey:           privKey,
	}
	client = &acmez.Client{
		Client: &acme.Client{
			Directory:  p.cfg.ACME.DirectoryURL,
			HTTPClient: acmeHTTPClient,
			UserAgent:  "ssl-cert-server",
			Logger:     zlog.Named("acmez"),
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeHTTP01:    p.httpSolver,
			acme.ChallengeTypeTLSALPN01: p.httpSolver,
		},
	}
	if cert.DNSCredential != "" {
		dnsCredential := p.cfg.GetDNSCredential(cert.DNSCredential)
		if dnsCredential != nil {
			dnsSolver, err := NewDNSSolver(dnsCredential)
			if err != nil {
				return account, nil, err
			}
			client.ChallengeSolvers[acme.ChallengeTypeDNS01] = dnsSolver
		}
	}
	account, err = client.NewAccount(ctx, account)
	return account, client, err
}

func (p *acmeImpl) issueCertificate(ctx context.Context, certName string, domains []string) (*acmeRespCertificate, error) {
	account, client, err := p.newACMEClient(ctx, certName)
	if err != nil {
		return nil, err
	}
	privKey, err := p.cfg.GeneratePrivateKey(certName)
	if err != nil {
		return nil, err
	}
	respCerts, err := client.ObtainCertificate(ctx, account, privKey, domains)
	if err != nil {
		return nil, err
	}
	if len(respCerts) == 0 || len(respCerts[0].ChainPEM) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}

	acmeCert := &acmeRespCertificate{
		PrivateKey:  pem.EncodeToMemory(utils.ToPEMBlock(privKey)),
		Certificate: respCerts[0].ChainPEM,
	}
	return acmeCert, nil
}

type acmeRespCertificate struct {
	PrivateKey  []byte
	Certificate []byte
}

func formatContact(emails ...string) []string {
	contact := make([]string, 0, len(emails))
	for _, email := range emails {
		contact = append(contact, "mailto:"+email)
	}
	return contact
}
