package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	mathrand "math/rand"
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
// Using custom httpClient which disables Keep-Alive should fix this issue.
var httpClient *http.Client

func init() {
	mathrand.Seed(timeNow().UnixNano())
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

func NewManager(wildcard *WildcardManager, managed *ManagedCertManager, ocspMgr *OCSPManager) *Manager {
	manager := &Manager{
		autocert: &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       Cfg.Storage.Cache,
			RenewBefore: time.Duration(Cfg.LetsEncrypt.RenewBefore) * 24 * time.Hour,
			Client:      &acme.Client{DirectoryURL: Cfg.LetsEncrypt.DirectoryURL},
			Email:       Cfg.LetsEncrypt.Email,
			HostPolicy:  Cfg.LetsEncrypt.HostPolicy,
		},
		ForceRSA: Cfg.LetsEncrypt.ForceRSA,
		wildcard: wildcard,
		managed:  managed,
		ocspMgr:  ocspMgr,
		log:      zlog.Named("manager").Sugar(),
	}
	return manager
}

type Manager struct {
	autocert *autocert.Manager
	ForceRSA bool

	wildcard *WildcardManager
	managed  *ManagedCertManager
	ocspMgr  *OCSPManager
	log      *zap.SugaredLogger
}

func (m *Manager) GetACMEAccount(ctx context.Context) (*acme.Account, *ecdsa.PrivateKey, error) {
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

func (m *Manager) KeyName(domain string) string {
	if !m.ForceRSA {
		return domain
	}
	return domain + "+rsa"
}

func (m *Manager) OCSPKeyName(domain string) string {
	return fmt.Sprintf("autocert|%s", m.KeyName(domain))
}

func (m *Manager) helloInfo(domain string) *tls.ClientHelloInfo {
	helloInfo := &tls.ClientHelloInfo{ServerName: domain}
	if !m.ForceRSA {
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

func (m *Manager) GetAutocertCertificate(name string) (*tls.Certificate, error) {
	helloInfo := m.helloInfo(name)
	cert, err := m.autocert.GetCertificate(helloInfo)
	if err != nil {
		return nil, err
	}
	m.watchCert(name)
	return cert, nil
}

func (m *Manager) watchCert(name string) {
	ocspKeyName := m.OCSPKeyName(name)
	m.ocspMgr.Watch(ocspKeyName, func() (*tls.Certificate, error) {
		helloInfo := m.helloInfo(name)
		return m.autocert.GetCertificate(helloInfo)
	})
}

func (m *Manager) GetAutocertALPN01Certificate(name string) (*tls.Certificate, error) {
	helloInfo := m.helloInfo(name)
	helloInfo.SupportedProtos = []string{acme.ALPNProto}
	return m.autocert.GetCertificate(helloInfo)
}

var rand63n = mathrand.Int63n

var testOCSPDidUpdateLoop = func(next time.Duration, err error) {}

var timeNow = time.Now
