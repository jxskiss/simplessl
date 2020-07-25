package main

import (
	"context"
	"flag"
	"regexp"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// StringArray implements flag.Value interface.
type StringArray []string

func (v *StringArray) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func (v *StringArray) String() string {
	return strings.Join(*v, ",")
}

var config struct {
	DomainList  StringArray
	PatternList StringArray

	ShowVersion bool
	Listen      string
	Before      int
	Email       string
	Staging     bool
	ForceRSA    bool

	// HostPolicy is built from DomainList and PatternList.
	HostPolicy autocert.HostPolicy

	// DirectoryURL will be set to staging api if option Staging is true,
	// else it will be Let's Encrypt production api.
	DirectoryURL string
}

func initFlags() {
	flag.Var(&config.DomainList,
		"domain",
		"allowed domain names (may be given multiple times)")
	flag.Var(&config.PatternList,
		"pattern",
		"allowed domain regex pattern using POSIX ERE (egrep) syntax, (may be given multiple times, will be ignored when domain parameters supplied)")

	flag.BoolVar(&config.ShowVersion,
		"version",
		false,
		"print version string and quit")
	flag.StringVar(&config.Listen,
		"listen",
		"127.0.0.1:8999",
		"listen address, be sure DON'T open to the world")
	flag.IntVar(&config.Before,
		"before",
		30,
		"renew certificates before how many days")
	flag.StringVar(&config.Email,
		"email",
		"",
		"contact email, if Let's Encrypt client's key is already registered, this is not used")
	flag.BoolVar(&config.Staging,
		"staging",
		false,
		"use Let's Encrypt staging directory (default false)")
	flag.BoolVar(&config.ForceRSA,
		"force-rsa",
		false,
		"generate certificates with 2048-bit RSA keys (default false)")

	flag.StringVar(&store.cacheDir,
		"cache-dir",
		"./secret-dir",
		"which directory to cache certificates, will be ignored if other storage provided")

	flag.Parse()
}

func prepareConfig() {
	var hostPolicy autocert.HostPolicy
	if len(config.DomainList) > 0 {
		hostPolicy = HostWhitelist(config.DomainList...)
	} else if len(config.PatternList) > 0 {
		patterns := make([]*regexp.Regexp, len(config.PatternList))
		for i, p := range config.PatternList {
			r := regexp.MustCompilePOSIX(p)
			patterns[i] = r
		}
		hostPolicy = RegexpWhitelist(patterns...)
	} else {
		// allow any domain by default
		hostPolicy = func(ctx context.Context, host string) error {
			return nil
		}
	}
	config.HostPolicy = hostPolicy

	if config.Staging {
		config.DirectoryURL = stagingDirectoryURL
	} else {
		config.DirectoryURL = acme.LetsEncryptURL
	}
}
