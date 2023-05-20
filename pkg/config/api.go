package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jxskiss/gopkg/v2/confr"
	"github.com/jxskiss/gopkg/v2/zlog"
	"go.uber.org/zap"
	"golang.org/x/net/idna"

	"github.com/jxskiss/simplessl/pkg/pb"
)

const (
	Version2 = "2"

	LetsEncryptURL        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func log() *zap.SugaredLogger {
	return zlog.Named("config").Sugar()
}

func LoadConfig(fn string) (*Config, error) {
	var version string
	{
		cfg := &versionDetector{}
		err := confr.Load(cfg, fn)
		if err != nil {
			return nil, fmt.Errorf("cannot detect config version: %v", err)
		}
		version = cfg.Version
	}

	var cfg *Config
	if version == Version2 {
		cfg = &Config{}
		err := confr.Load(cfg, fn)
		if err != nil {
			return nil, err
		}
	} else {
		log().Warnf("[DEPRECATED] try loading legacy configuration: %v", fn)
		v1Cfg := &v1Config{}
		err := confr.Load(v1Cfg, fn)
		if err != nil {
			return nil, err
		}
		cfg = v1Cfg.ToV2Config()
	}
	err := cfg.prepare()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) prepare() error {
	c.state = state{
		managedCertMap:   make(map[string]*ManagedCertificate),
		acmeAccountMap:   make(map[string]*ACMEAccount),
		acmeNamedCertMap: make(map[string]*ACMECertificate),
		dnsCredentialMap: make(map[string]*DNSCredential),
	}
	for _, cert := range c.Managed.Certificates {
		c.state.managedCertMap[cert.Name] = cert
	}
	c.state.acmeAccountMap[c.ACME.DefaultAccount.Email] = c.ACME.DefaultAccount
	for _, acc := range c.ACME.Accounts {
		c.state.acmeAccountMap[acc.Email] = acc
	}
	for _, cert := range c.ACME.Named.Certificates {
		c.state.acmeNamedCertMap[cert.Name] = cert
	}
	for _, credential := range c.ACME.DNSCredentials {
		for k, v := range credential.Env {
			credential.Env[k] = os.ExpandEnv(v)
		}
		c.state.dnsCredentialMap[credential.Name] = credential
	}
	return nil
}

type state struct {
	managedCertMap   map[string]*ManagedCertificate
	acmeAccountMap   map[string]*ACMEAccount
	acmeNamedCertMap map[string]*ACMECertificate
	dnsCredentialMap map[string]*DNSCredential

	domainMatchCache sync.Map // domain -> *domainMatchResult
}

type domainMatchResult struct {
	typ  pb.Certificate_Type
	name string
}

func (c *Config) IsManagedCertEnableOCSPStapling(name string) bool {
	cert := c.state.managedCertMap[name]
	return cert != nil && !cert.NoOCSPStapling
}

func (c *Config) GetManagedCertReloadInterval() time.Duration {
	d, _ := time.ParseDuration(c.Managed.ReloadInterval)
	if d <= 0 {
		d = 10 * time.Minute
	}
	return d
}

func (c *Config) GetNamedACMECertificate(name string) *ACMECertificate {
	return c.state.acmeNamedCertMap[name]
}

func (c *Config) GetDNSCredential(name string) *DNSCredential {
	return c.state.dnsCredentialMap[name]
}

func (c *Config) CheckCertTypeByName(name string) (typ pb.Certificate_Type, resultName string) {
	if c.state.managedCertMap[name] != nil {
		return pb.Certificate_MANAGED, name
	}
	if c.state.acmeNamedCertMap[name] != nil {
		return pb.Certificate_ACME_NAMED, name
	}
	return pb.Certificate_UNKNOWN, ""
}

func (c *Config) CheckCertTypeByDomain(domain string) (typ pb.Certificate_Type, name string) {
	if cached, ok := c.state.domainMatchCache.Load(domain); ok && cached != nil {
		result := cached.(*domainMatchResult)
		return result.typ, result.name
	}

	typ, name = c.matchDomain(domain)
	c.state.domainMatchCache.Store(domain, &domainMatchResult{
		typ:  typ,
		name: name,
	})
	return
}

func (c *Config) matchDomain(domain string) (typ pb.Certificate_Type, name string) {
	for _, cert := range c.Managed.Certificates {
		if matchDomainList(cert.Domains, domain) ||
			matchDomainRegex(cert.DomainRegex, domain) {
			return pb.Certificate_MANAGED, cert.Name
		}
	}
	for _, cert := range c.ACME.Named.Certificates {
		if matchDomainList(cert.Domains, domain) {
			return pb.Certificate_ACME_NAMED, cert.Name
		}
	}
	if matchDomainList(c.ACME.OnDemand.Domains, domain) ||
		matchDomainRegex(c.ACME.OnDemand.DomainRegex, domain) {
		return pb.Certificate_ACME_ON_DEMAND, domain
	}

	if !c.SelfSigned.Enable {
		return pb.Certificate_UNKNOWN, ""
	}
	if !c.SelfSigned.CheckDomainName {
		return pb.Certificate_SELF_SIGNED, ""
	}
	if matchDomainList(c.SelfSigned.Domains, domain) ||
		matchDomainRegex(c.SelfSigned.DomainRegex, domain) {
		return pb.Certificate_SELF_SIGNED, ""
	}
	return pb.Certificate_UNKNOWN, ""
}

func (c *Config) GetACMEConfig(certName string) (acc *ACMEAccount, cert *ACMECertificate, err error) {
	acc = c.ACME.DefaultAccount
	if certName != "" {
		cert = c.state.acmeNamedCertMap[certName]
		if cert != nil && cert.Account != "" {
			tmp := c.state.acmeAccountMap[cert.Account]
			if tmp != nil {
				acc = tmp
			}
		}
	}
	return acc, cert, nil
}

func (c *Config) GeneratePrivateKey(certName string) (crypto.Signer, error) {
	var cert *ACMECertificate
	if certName != "" {
		cert = c.state.acmeNamedCertMap[certName]
	}
	if cert != nil {
		if cert.ForceRSA {
			return rsa.GenerateKey(rand.Reader, 2048)
		}
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if c.ACME.ForceRSA {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type versionDetector struct {
	Version string `yaml:"version"`
}

// https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.4
// The domain name MUST be encoded in the form in which it would appear in a certificate.
// That is, it MUST be encoded according to the rules in Section 7 of [RFC5280].
//
// https://www.rfc-editor.org/rfc/rfc5280.html#section-7
func sanitizeDomain(domains []string) ([]string, error) {
	var sanitizedDomains []string
	for _, domain := range domains {
		sanitizedDomain, err := idna.ToASCII(domain)
		if err != nil {
			return nil, err
		} else {
			sanitizedDomains = append(sanitizedDomains, sanitizedDomain)
		}
	}
	return sanitizedDomains, nil
}
