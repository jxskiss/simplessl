package server

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"regexp"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"gopkg.in/yaml.v2"
)

var DefaultSelfSignedOrganization = []string{"SSL Cert Server Self-Signed"}

type redisConfig struct {
	Addr   string `yaml:"addr"`   // default: "127.0.0.1:6379"
	Prefix string `yaml:"prefix"` // default: ""
}

type config struct {
	Listen  string `yaml:"listen"`   // default: "127.0.0.1:8999"
	PIDFile string `yaml:"pid_file"` // default: "ssl-cert-server.pid"

	Storage struct {
		Type     string      `yaml:"type"`      // dir_cache | redis, default: dir_cache
		DirCache string      `yaml:"dir_cache"` // default: "./secret-dir"
		Redis    redisConfig `yaml:"redis"`

		// Cache is used by Manager to store and retrieve previously obtained certificates
		// and other account data as opaque blobs.
		Cache autocert.Cache `yaml:"-"`
	} `yaml:"storage"`

	Managed []struct {
		Pattern string `yaml:"pattern"`
		CertKey string `yaml:"cert_key"`

		Regex *regexp.Regexp `yaml:"-"`
	} `yaml:"managed"`

	LetsEncrypt struct {
		Staging     bool     `yaml:"staging"`      // default: false
		ForceRSA    bool     `yaml:"force_rsa"`    // default: false
		RenewBefore int      `yaml:"renew_before"` // default: 30
		Email       string   `yaml:"email"`
		Domains     []string `yaml:"domains"`
		REPatterns  []string `yaml:"re_patterns"`

		// HostPolicy is built from DomainList and PatternList.
		// By default, any valid domain name is allowed if neither
		// domain list nor regex pattern list provided. In such case,
		// all requests will go to Let's Encrypt, and the following self_signed
		// configuration will not take effect.
		HostPolicy autocert.HostPolicy `yaml:"-"`

		// DirectoryURL will be set to Let's Encrypt staging api if the
		// option Staging is true, else it will be the production api.
		DirectoryURL string `yaml:"-"`
	} `yaml:"lets_encrypt"`

	SelfSigned struct {
		Enable       bool     `yaml:"enable"`       // default: false
		CheckSNI     bool     `yaml:"check_sni"`    // default: false
		ValidDays    int      `yaml:"valid_days"`   // default: 365
		Organization []string `yaml:"organization"` // default: ["SSL Cert Server Self-Signed"]
		CertKey      string   `yaml:"cert_key"`     // default: "self_signed"
	} `yaml:"self_signed"`
}

func (p *config) setupDefaultOptions() {
	setDefault(&Cfg.Listen, "127.0.0.1:8999")
	setDefault(&Cfg.PIDFile, "ssl-cert-server.pid")

	setDefault(&Cfg.Storage.Type, "dir_cache")
	setDefault(&Cfg.Storage.DirCache, "./secret-dir")
	setDefault(&Cfg.Storage.Redis.Addr, "127.0.0.1:6379")

	setDefault(&Cfg.LetsEncrypt.RenewBefore, 30)
	if Cfg.LetsEncrypt.Staging {
		Cfg.LetsEncrypt.DirectoryURL = stagingDirectoryURL
	} else {
		Cfg.LetsEncrypt.DirectoryURL = acme.LetsEncryptURL
	}

	setDefault(&Cfg.SelfSigned.ValidDays, 365)
	setDefault(&Cfg.SelfSigned.CertKey, "self_signed")
	if len(Cfg.SelfSigned.Organization) == 0 {
		Cfg.SelfSigned.Organization = DefaultSelfSignedOrganization
	}
}

func (p *config) buildHostPolicy() {
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
				log.Fatalf("[FATAL] server: failed compile lets_encrypte domain pattern: %q, %v", p, err)
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

var Cfg = &config{}

var Flags struct {
	ShowVersion bool   // default: false
	ConfigFile  string // default: "./conf.yaml"
}

func InitFlags() {
	flag.BoolVar(&Flags.ShowVersion, "version", false, "print version string and quit")
	flag.StringVar(&Flags.ConfigFile, "config", "./conf.yaml", "configuration filename")
	flag.Parse()
}

func InitConfig() {
	confbuf, err := ioutil.ReadFile(Flags.ConfigFile)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("[FATAL] server: failed read configuration: %v", err)
	}
	if len(confbuf) > 0 {
		err = yaml.UnmarshalStrict(confbuf, Cfg)
		if err != nil {
			log.Fatalf("[FATAL] server: failed read configuration: %v", err)
		}
	}

	// Prepare configuration.

	Cfg.setupDefaultOptions()
	Cfg.buildHostPolicy()

	switch Cfg.Storage.Type {
	case "dir_cache":
		Cfg.Storage.Cache, _ = NewDirCache(Cfg.Storage.DirCache)
	case "redis":
		Cfg.Storage.Cache, err = NewRedisCache(Cfg.Storage.Redis)
		if err != nil {
			log.Fatalf("[FATAL] server: failed setup redis storage: %v", err)
		}
	}

	for i := range Cfg.Managed {
		pattern := Cfg.Managed[i].Pattern
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Fatalf("[FATAL] server: failed compile managed domain pattern: %q, %v", pattern, err)
		}
		Cfg.Managed[i].Regex = re
	}
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
