package tlsconfig

import (
	"fmt"
	"regexp"
	"sync"

	"golang.org/x/net/idna"
)

type Options struct {
	// AllowDomains optionally specifies which host names are allowed to
	// respond to. If not specified, any valid domain will trigger
	// certificate request towards the backend ssl cert server, and the
	// backend server take responsibility to check host policy.
	//
	// It's recommended to set this option, it helps to reduce influence
	// of unwelcome requests, such as DDOS, etc.
	AllowDomains []string

	// AllowDomainRegex optionally validates host names using regular expressions.
	//
	// If AllowDomains and AllowDomainRegex are both configured,
	// a domain name will be allowed if it matches either one.
	AllowDomainRegex []string

	// PreloadDomains optionally specifies host names to preload certificates
	// when initializing the TLS config. It helps to accelerate the
	// connecting speed of the first requests after the server started.
	// It's recommended to set this option for production deployment to
	// optimize end-user experience.
	//
	// As you may guess, this option will slow down the server startup
	// time, you may enable the following PreloadAsync option to preload
	// the certificates asynchronously in background.
	PreloadDomains []string
	PreloadAsync   bool

	// DisableStapling optionally disables OCSP stapling.
	DisableStapling bool

	// ErrorLog specifies an optional function to log error messages.
	// If nil, error messages will be logged using the default logger from
	// "log" package.
	ErrorLog func(format string, args ...interface{})
}

func (opts Options) makeHostPolicy() func(string) error {
	if len(opts.AllowDomains) == 0 && len(opts.AllowDomainRegex) == 0 {
		return nil
	}

	hostMap := make(map[string]bool, len(opts.AllowDomains))
	reList := make([]*regexp.Regexp, 0)
	for _, h := range opts.AllowDomains {
		h, err := idna.Lookup.ToASCII(h)
		if err != nil {
			if opts.ErrorLog != nil {
				opts.ErrorLog("tlsconfig: domain name contains invalid character: %q", h)
			}
			continue
		}
		hostMap[h] = true
	}
	for _, reStr := range opts.AllowDomainRegex {
		re, err := regexp.Compile(reStr)
		if err != nil {
			if opts.ErrorLog != nil {
				opts.ErrorLog("tlsconfig: cannot compile domain regexp: %q", reStr)
			}
			continue
		}
		reList = append(reList, re)
	}

	var cache sync.Map
	type cacheErr struct {
		error
	}

	return func(host string) error {
		// Note that host has already been converted to ASCII
		// using idna.Lookup.ToASCII by the caller.
		if cached, ok := cache.Load(host); ok {
			return cached.(cacheErr).error
		}

		var result error
		allow := hostMap[host]
		if !allow {
			for _, re := range reList {
				if re.MatchString(host) {
					allow = true
					break
				}
			}
		}
		if !allow {
			result = fmt.Errorf("tlsconfig: host %q not allowed", host)
		}
		cache.Store(host, cacheErr{result})
		return result
	}
}

func (c *Client) preloadDomains(async bool, domains ...string) {
	loadFunc := func() {
		for _, domainName := range domains {
			_, err := c.getCertificate(domainName)
			if err != nil {
				c.opts.ErrorLog("[WARN] tlsconfig: failed preload certificate: domain= %s err= %v", domainName, err)
			}
		}
	}
	if async {
		go loadFunc()
	} else {
		loadFunc()
	}
}
