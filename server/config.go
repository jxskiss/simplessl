package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/jxskiss/gopkg/v2/confr"
	"github.com/jxskiss/gopkg/v2/set"
	"github.com/jxskiss/gopkg/v2/zlog"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

var DefaultSelfSignedOrganization = []string{"SSL Cert Server Self-Signed"}

type redisConfig struct {
	Addr   string `yaml:"addr" default:"127.0.0.1:6379"`
	Prefix string `yaml:"prefix"` // default: ""
}

type dnsCredential struct {
	Name     string            `yaml:"name"`
	Provider string            `yaml:"provider"`
	Env      map[string]string `yaml:"env"`
}

type wildcardItem struct {
	RootDomain string   `yaml:"root_domain"`
	Credential string   `yaml:"credential"`
	Domains    []string `yaml:"domains"`
}

func (p *wildcardItem) Match(name string) bool {
	if !strings.HasSuffix(name, p.RootDomain) {
		return false
	}
	for _, domain := range p.Domains {
		if !strings.HasPrefix(domain, "*.") {
			if domain == name {
				return true
			}
			continue
		}
		// wildcard domain
		leftmost := strings.TrimSuffix(name, domain[2:])
		if !strings.HasSuffix(leftmost, ".") {
			continue
		}
		leftmost = leftmost[:len(leftmost)-1]
		if strings.ContainsRune(leftmost, '.') {
			continue
		}
		_, err := idna.Lookup.ToASCII(leftmost)
		return err == nil
	}
	return false
}

type Config struct {
	Listen  string `yaml:"listen" default:"127.0.0.1:8999"`
	PIDFile string `yaml:"pid_file" default:"ssl-cert-server.pid"`

	Storage struct {
		Type     string      `yaml:"type" default:"dir_cache"`
		DirCache string      `yaml:"dir_cache" default:"./secret-dir"`
		Redis    redisConfig `yaml:"redis"`

		// Cache is used to store and retrieve previously obtained certificates
		// and other account data as opaque blobs.
		Cache autocert.Cache `yaml:"-"`
	} `yaml:"storage"`

	Managed []struct {
		Pattern string `yaml:"pattern"`
		CertKey string `yaml:"cert_key"`

		Regex *regexp.Regexp `yaml:"-"`
	} `yaml:"managed"`

	LetsEncrypt struct {
		Staging     bool     `yaml:"staging"`   // default: false
		ForceRSA    bool     `yaml:"force_rsa"` // default: false
		RenewBefore int      `yaml:"renew_before" default:"30"`
		Email       string   `yaml:"email"`
		Domains     []string `yaml:"domains"`
		REPatterns  []string `yaml:"re_patterns"`

		// HostPolicy is built from DomainList and PatternList.
		// By default, any valid domain name is allowed if neither
		// domain list nor regex pattern list provided. In such case,
		// all requests will go to Let's Encrypt, and the following self_signed
		// configuration will not take effect.
		HostPolicy autocert.HostPolicy `yaml:"-" json:"-"`

		// DirectoryURL will be set to Let's Encrypt staging api if the
		// option Staging is true, else it will be the production api.
		DirectoryURL string `yaml:"-"`
	} `yaml:"lets_encrypt"`

	Wildcard struct {
		LegoDataPath   string           `yaml:"lego_data_path"`
		DNSCredentials []*dnsCredential `yaml:"dns_credentials"`
		Certificates   []*wildcardItem  `yaml:"certificates"`

		credentialMap   map[string]*dnsCredential
		certificateList []*wildcardItem
	} `yaml:"wildcard"`

	SelfSigned struct {
		Enable       bool     `yaml:"enable"`    // default: false
		CheckSNI     bool     `yaml:"check_sni"` // default: false
		ValidDays    int      `yaml:"valid_days" default:"365"`
		Organization []string `yaml:"organization"` // default: ["SSL Cert Server Self-Signed"]
		CertKey      string   `yaml:"cert_key" default:"self_signed"`
	} `yaml:"self_signed"`
}

func (p *Config) setupDefaultOptions() {
	if p.LetsEncrypt.Staging {
		p.LetsEncrypt.DirectoryURL = stagingDirectoryURL
	} else {
		p.LetsEncrypt.DirectoryURL = acme.LetsEncryptURL
	}

	defaultLegoDataPath := filepath.Join(p.Storage.DirCache, ".lego")
	setDefault(&p.Wildcard.LegoDataPath, defaultLegoDataPath)

	if len(p.SelfSigned.Organization) == 0 {
		p.SelfSigned.Organization = DefaultSelfSignedOrganization
	}
}

func (p *Config) buildHostPolicy() {
	var listPolicy autocert.HostPolicy
	var rePolicy autocert.HostPolicy
	if len(p.LetsEncrypt.Domains) > 0 {
		listPolicy = HostWhitelist(p.LetsEncrypt.Domains...)
	}
	if len(p.LetsEncrypt.REPatterns) > 0 {
		patterns := make([]*regexp.Regexp, len(p.LetsEncrypt.REPatterns))
		for i, p := range p.LetsEncrypt.REPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				zlog.Fatalf("config: failed compile lets_encrypt domain pattern: %q, %v", p, err)
			}
			patterns[i] = re
		}
		rePolicy = RegexpWhitelist(patterns...)
	}

	// no domains specified, allow any valid domain by default
	if listPolicy == nil && rePolicy == nil {
		p.LetsEncrypt.HostPolicy = checkHostIsValid
		return
	}

	// first check plain domain list
	// then check regex domain patterns
	p.LetsEncrypt.HostPolicy = func(ctx context.Context, host string) (err error) {
		if listPolicy != nil {
			if err = listPolicy(ctx, host); err == nil {
				return nil
			}
		}
		if rePolicy != nil {
			if err = rePolicy(ctx, host); err == nil {
				return nil
			}
		}
		return err
	}
}

func (p *Config) prepareWildcardConfig() error {
	credentialMap := make(map[string]*dnsCredential, len(p.Wildcard.DNSCredentials))
	for _, cred := range p.Wildcard.DNSCredentials {
		if cred.Name == "" || cred.Provider == "" {
			return fmt.Errorf("dns credential's name/provider cannot be empty")
		}
		if _, ok := credentialMap[cred.Name]; ok {
			return fmt.Errorf("dns credential %s is duplicate", cred.Name)
		}
		credentialMap[cred.Name] = cred
	}
	p.Wildcard.credentialMap = credentialMap

	certRootDomainSet := set.New[string]()
	for _, cert := range p.Wildcard.Certificates {
		if cert.RootDomain == "" {
			return fmt.Errorf("certificate root domain cannot be empty")
		}
		if certRootDomainSet.Contains(cert.RootDomain) {
			return fmt.Errorf("certificate root domain %s is duplicate", cert.RootDomain)
		}
		if credentialMap[cert.Credential] == nil {
			return fmt.Errorf("dns credential %s is not configrured", cert.Credential)
		}
		if err := validateWildcardDomains(cert.Domains); err != nil {
			return err
		}
		p.Wildcard.certificateList = append(p.Wildcard.certificateList, cert)
	}

	return nil
}

func (p *Config) CheckWildcardDomain(name string) *wildcardItem {
	for _, item := range p.Wildcard.certificateList {
		if item.Match(name) {
			return item
		}
	}
	return nil
}

func (p *Config) validate() error {
	if p.LetsEncrypt.Email == "" {
		return errors.New("lets_encrypt.email cannot be empty")
	}
	return nil
}

func (p *Config) IsManagedDomain(domain string) (certKey string, ok bool) {
	for _, x := range p.Managed {
		if x.Regex.MatchString(domain) {
			return x.CertKey, true
		}
	}
	return "", false
}

func (p *Config) IsWildcardDomain(domain string) (item *wildcardItem, ok bool) {
	if len(p.Wildcard.certificateList) == 0 {
		return nil, false
	}

	type checkResult struct {
		item *wildcardItem
		ok   bool
	}
	if val, ok := wildcardDomainCheckResultCache.Load(domain); ok {
		result := val.(*checkResult)
		return result.item, result.ok
	}

	item = p.CheckWildcardDomain(domain)
	if item != nil {
		ok = true
	}
	wildcardDomainCheckResultCache.Store(domain, &checkResult{item, ok})
	return item, ok
}

func (p *Config) IsSelfSignedAllowed(domain string) bool {
	if !p.SelfSigned.Enable {
		return false
	}
	if p.SelfSigned.CheckSNI {
		if err := checkHostIsValid(context.Background(), domain); err != nil {
			return false
		}
	}
	return true
}

func InitConfig(opts Opts) *Config {
	var cfg = &Config{}
	err := confr.Load(cfg, opts.ConfigFile)
	if err != nil {
		zlog.Fatalf("config: failed load configuration: %v", err)
	}

	cfg.setupDefaultOptions()
	cfg.buildHostPolicy()

	err = cfg.prepareWildcardConfig()
	if err != nil {
		zlog.Fatalf("config: failed prepare wildcard config: %v", err)
	}

	switch cfg.Storage.Type {
	case "dir_cache":
		cfg.Storage.Cache, err = NewDirCache(cfg.Storage.DirCache)
		if err != nil {
			zlog.Fatalf("config: failed setup dir_cache storage: %v", err)
		}
	case "redis":
		cfg.Storage.Cache, err = NewRedisCache(cfg.Storage.Redis)
		if err != nil {
			zlog.Fatalf("config: failed setup redis storage: %v", err)
		}
	}

	for i := range cfg.Managed {
		pattern := cfg.Managed[i].Pattern
		re, err := regexp.Compile(pattern)
		if err != nil {
			zlog.Fatalf("config: failed compile managed domain pattern: %q, %v", pattern, err)
		}
		cfg.Managed[i].Regex = re
	}

	err = cfg.validate()
	if err != nil {
		zlog.Fatalf("config: failed validate configuration: %v", err)
	}

	return cfg
}

func setDefault(dst interface{}, value interface{}) {
	dstVal := reflect.ValueOf(dst)
	if reflect.Indirect(dstVal).IsZero() {
		dstVal.Elem().Set(reflect.ValueOf(value))
	}
}

func checkHostIsValid(ctx context.Context, host string) (err error) {
	if host == "" {
		return ErrHostNotPermitted
	}
	if !strings.Contains(strings.Trim(host, "."), ".") {
		return ErrHostNotPermitted
	}
	return nil
}

var wildcardDomainRE = regexp.MustCompile(`^(\*\.)?([\w-]+\.)+\w+$`)

func validateWildcardDomains(domains []string) error {
	if len(domains) == 0 {
		return errors.New("must have at least one domain")
	}
	for _, domain := range domains {
		isValid := wildcardDomainRE.MatchString(domain)
		if !isValid {
			return fmt.Errorf("domain name %q is invalid", domain)
		}
	}
	return nil
}
