package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const stagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

// httpClient is used to do http request instead of the default http.DefaultClient.
// The OCSP server of Let's Encrypt certificates seems working improperly, gives
// `Unsolicited response received on idle HTTP channel starting with "HTTP/1.0 408 Request Time-out"`
// errors constantly after the service has been running for a long time.
// Using custom httpClient which disables Keep-Alive fixes this issue.
var httpClient *http.Client

func init() {
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				DualStack: true,
			}).DialContext,
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

var ErrCacheMiss = autocert.ErrCacheMiss
var ErrHostNotPermitted = errors.New("host not permitted")

func HostWhitelist(hosts ...string) autocert.HostPolicy {
	whitelist := autocert.HostWhitelist(hosts...)
	return func(ctx context.Context, host string) error {
		if whitelist(ctx, host) != nil {
			return ErrHostNotPermitted
		}
		return nil
	}
}

func RegexpWhitelist(patterns ...*regexp.Regexp) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		for _, p := range patterns {
			if p.MatchString(host) {
				return nil
			}
		}
		return ErrHostNotPermitted
	}
}

func NewAutocertManager(cfg *Config, ocspMgr *OCSPManager) *AutocertManager {
	manager := &AutocertManager{
		autocert: &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       cfg.Storage.Cache,
			RenewBefore: time.Duration(cfg.LetsEncrypt.RenewBefore) * 24 * time.Hour,
			Client:      &acme.Client{DirectoryURL: cfg.LetsEncrypt.DirectoryURL},
			Email:       cfg.LetsEncrypt.Email,
			HostPolicy:  cfg.LetsEncrypt.HostPolicy,
		},
		forceRSA: cfg.LetsEncrypt.ForceRSA,
		ocspMgr:  ocspMgr,
		log:      zlog.Named("manager").Sugar(),
	}
	return manager
}

type AutocertManager struct {
	autocert *autocert.Manager
	forceRSA bool
	ocspMgr  *OCSPManager
	log      *zap.SugaredLogger
}

func (m *AutocertManager) GetACMEAccount(ctx context.Context) (*acme.Account, *ecdsa.PrivateKey, error) {
	acmeCli, err := _autocert_Manager_acmeClient(m.autocert, ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get ACME client: %w", err)
	}
	account, err := acmeCli.GetReg(ctx, "")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get ACME account: %w", err)
	}
	return account, acmeCli.Key.(*ecdsa.PrivateKey), nil
}

func (m *AutocertManager) KeyName(domain string) string {
	if !m.forceRSA {
		return domain
	}
	return domain + "+rsa"
}

func (m *AutocertManager) OCSPKeyName(domain string) string {
	return fmt.Sprintf("autocert|%s", m.KeyName(domain))
}

func (m *AutocertManager) helloInfo(domain string) *tls.ClientHelloInfo {
	helloInfo := &tls.ClientHelloInfo{ServerName: domain}
	if !m.forceRSA {
		helloInfo.SignatureSchemes = append(helloInfo.SignatureSchemes,
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		)
		helloInfo.SupportedCurves = append(helloInfo.SupportedCurves, tls.CurveP256, tls.CurveP384, tls.CurveP521)
		helloInfo.CipherSuites = append(helloInfo.CipherSuites,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		)
	}
	return helloInfo
}

func (m *AutocertManager) GetAutocertCertificate(name string) (*tls.Certificate, error) {
	helloInfo := m.helloInfo(name)
	cert, err := m.autocert.GetCertificate(helloInfo)
	if err != nil {
		return nil, err
	}
	m.watchCert(name)
	return cert, nil
}

func (m *AutocertManager) watchCert(name string) {
	ocspKeyName := m.OCSPKeyName(name)
	m.ocspMgr.Watch(ocspKeyName, func() (*tls.Certificate, error) {
		helloInfo := m.helloInfo(name)
		return m.autocert.GetCertificate(helloInfo)
	})
}

func (m *AutocertManager) GetAutocertALPN01Certificate(name string) (*tls.Certificate, error) {
	helloInfo := m.helloInfo(name)
	helloInfo.SupportedProtos = []string{acme.ALPNProto}
	return m.autocert.GetCertificate(helloInfo)
}
