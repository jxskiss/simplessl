package tlsconfig

import (
	"fmt"
	"log"

	"golang.org/x/net/idna"
)

type Options struct {
	AllowDomains   []string
	PreloadDomains []string
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

func (c *Client) preloadDomains(domains ...string) {
	for _, domainName := range domains {
		_, err := c.getCertificate(domainName)
		if err != nil {
			log.Printf("[WARN] tlsconfig: failed preload certificate: %s: %v", domainName, err)
		}
	}
}
