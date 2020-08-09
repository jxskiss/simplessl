package tlsconfig

import (
	"fmt"
	"log"

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
}

func makeHostWhitelist(hosts ...string) func(string) error {
	if len(hosts) == 0 {
		return nil
	}
	whitelist := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if h, err := idna.Lookup.ToASCII(h); err == nil {
			whitelist[h] = true
		}
	}
	return func(host string) error {
		if !whitelist[host] {
			return fmt.Errorf("tlsconfig: host %q not allowed", host)
		}
		return nil
	}
}

func (c *Client) preloadDomains(async bool, domains ...string) {
	loadFunc := func() {
		for _, domainName := range domains {
			_, err := c.getCertificate(domainName)
			if err != nil {
				log.Printf("[WARN] tlsconfig: failed preload certificate: domain= %s err= %v", domainName, err)
			}
		}
	}
	if async {
		go loadFunc()
	} else {
		loadFunc()
	}
}
