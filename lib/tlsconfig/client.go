package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

type cacheItem struct {
	cert *tls.Certificate

	certRefresh int64
	certExpire  int64

	staplingRefresh int64
	staplingExpire  int64
}

type Client struct {
	serverHost string
	opts       *Options
	hostPolicy func(name string) error

	cache sync.Map
}

func NewClient(sslCertServerHost string, opts *Options) *Client {
	if !strings.HasPrefix(sslCertServerHost, "http://") {
		sslCertServerHost = "http://" + sslCertServerHost
	}
	sslCertServerHost = strings.TrimSuffix(sslCertServerHost, "/")
	client := &Client{
		serverHost: sslCertServerHost,
	}

	go client.watch()

	if opts != nil {
		// make host policy
		client.hostPolicy = makeHostWhitelist(opts.AllowDomains...)

		// preload certificates for pre-defined domain names
		client.preloadDomains(opts.PreloadAsync, opts.PreloadDomains...)
	}

	return client
}

func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("tlsconfig: missing server name")
	}
	if !strings.Contains(strings.Trim(name, "."), ".") {
		return nil, errors.New("tlsconfig: server name component count invalid")
	}

	// Note that this conversion is necessary because some server names in the handshakes
	// started by some clients (such as cURL) are not converted to Punycode, which will
	// prevent us from obtaining certificates for them. In addition, we should also treat
	// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
	// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
	//
	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("tlsconfig: server name contains invalid character")
	}

	if c.hostPolicy != nil {
		if err := c.hostPolicy(name); err != nil {
			return nil, err
		}
	}

	cert, err := c.getCertificate(name)
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: failed get certificate: %v", err)
	}
	return cert, err
}

func (c *Client) getCertificate(domainName string) (*tls.Certificate, error) {
	cacheKey := domainName
	cacheVal, ok := c.cache.Load(cacheKey)
	if ok {
		now := time.Now().Unix()
		cached := cacheVal.(*cacheItem)
		// in case the cached OCSP stapling is expired, abandon it
		if cached.staplingExpire > 0 && cached.staplingExpire <= now {
			newCert := *cached.cert
			newCert.OCSPStaple = nil
			newCacheItem := &cacheItem{
				cert:            &newCert,
				certRefresh:     cached.certRefresh,
				certExpire:      cached.certExpire,
				staplingRefresh: 0,
				staplingExpire:  0,
			}
			c.cache.Store(cacheKey, newCacheItem)
			cached = newCacheItem
		}
		return cached.cert, nil
	}

	// first request for a new domain, give it a long time
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cert, certExpire, certRefresh, err := c.requestCertificate(ctx, domainName)
	if err != nil {
		return nil, err
	}

	// If OCSP is enabled, get it.
	// And since OCSP stapling is optional, we don't fail the server request
	// in case of OCSP stapling unavailable.
	var stapling []byte
	var staplingRefresh, staplingExpire int64
	if len(cert.Leaf.OCSPServer) > 0 {
		stapling, staplingExpire, staplingRefresh, err = c.requestStapling(ctx, domainName)
		if err != nil {
			log.Printf("[WARN] tlsconfig: failed request OCSP stapling: domain= %s err= %v", domainName, err)
		}
	}

	cert.OCSPStaple = stapling
	cacheItem := &cacheItem{
		cert:            cert,
		certRefresh:     certRefresh,
		certExpire:      certExpire,
		staplingRefresh: staplingRefresh,
		staplingExpire:  staplingExpire,
	}
	c.cache.Store(cacheKey, cacheItem)
	return cacheItem.cert, nil
}

func (c *Client) requestCertificate(ctx context.Context, domainName string) (
	certificate *tls.Certificate, expireAt, refreshAt int64, err error,
) {
	var response struct {
		Cert     string `json:"cert"`
		PKey     string `json:"pkey"`
		ExpireAt int64  `json:"expire_at"` // seconds since epoch
		TTL      int64  `json:"ttl"`       // in seconds
	}

	apiPath := c.serverHost + "/cert/" + domainName
	req, err := http.NewRequestWithContext(ctx, "GET", apiPath, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("bad http status %d", resp.StatusCode)
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return
	}
	cert, err := tls.X509KeyPair([]byte(response.Cert), []byte(response.PKey))
	if err != nil {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	cert.Leaf = leaf

	certificate = &cert
	expireAt = response.ExpireAt
	refreshAt = time.Now().Unix() + response.TTL
	return
}

func (c *Client) requestStapling(ctx context.Context, domainName string) (
	stapling []byte, expireAt, refreshAt int64, err error,
) {
	apiPath := c.serverHost + "/ocsp/" + domainName
	req, err := http.NewRequestWithContext(ctx, "GET", apiPath, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("bad http status %d", resp.StatusCode)
		return
	}
	stapling, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	expireAt, _ = strconv.ParseInt(resp.Header.Get("X-Expire-At"), 10, 64)
	ttl, _ := strconv.ParseInt(resp.Header.Get("X-TTL"), 10, 64)
	refreshAt = now + ttl
	return
}

func (c *Client) watch() {
	ticker := time.Minute
	for range time.Tick(ticker) {

		// in case of error, retry 2 times with one second interval
		for i := 0; i < 3; i++ {
			cached := make(map[string]*cacheItem)
			c.cache.Range(func(k, v interface{}) bool {
				cached[k.(string)] = v.(*cacheItem)
				return true
			})
			err := c.refresh(cached)
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
	}
}

func (c *Client) refresh(cached map[string]*cacheItem) error {

	var certErr error
	var staplingErr error

	bgctx := context.Background()
	now := time.Now().Unix()
	for domainName, citem := range cached {
		if citem.certRefresh > now && citem.staplingRefresh > now {
			continue
		}

		// certificate or OCSP stapling comes to TTL, do refresh

		// shallow copy the certificate to avoid data race
		// we may change the OCSPStaple below
		cert := *citem.cert

		newCacheItem := &cacheItem{
			cert:            &cert,
			certRefresh:     citem.certRefresh,
			certExpire:      citem.certExpire,
			staplingRefresh: citem.staplingRefresh,
			staplingExpire:  citem.staplingExpire,
		}

		ctx, cancel := context.WithTimeout(bgctx, time.Second)
		if newCacheItem.certRefresh <= now {
			newCert, expireAt, refreshAt, err := c.requestCertificate(ctx, domainName)
			if err != nil {
				log.Printf("[WARN] tlsconfig: failed refresh certificate: domain= %s err= %v", domainName, err)
				if certErr == nil {
					certErr = err
				}
			} else {
				newCacheItem.cert = newCert
				newCacheItem.certRefresh = refreshAt
				newCacheItem.certExpire = expireAt
			}
		}
		if newCacheItem.staplingRefresh <= now {
			newStapling, expireAt, refreshAt, err := c.requestStapling(ctx, domainName)
			if err != nil {
				log.Printf("[WARN] tlsconfig: failed refresh OCSP stapling: domain= %s err= %v", domainName, err)
				if staplingErr == nil {
					staplingErr = err
				}
				// if the stapling is going to expire, abandon it
				if newCacheItem.staplingExpire-now < 120 {
					newCacheItem.cert.OCSPStaple = nil
					newCacheItem.staplingRefresh = 0
					newCacheItem.staplingExpire = 0
				}
			} else {
				newCacheItem.cert.OCSPStaple = newStapling
				newCacheItem.staplingRefresh = refreshAt
				newCacheItem.staplingExpire = expireAt
			}
		}
		cancel()

		c.cache.Store(domainName, newCacheItem)
	}

	if certErr != nil {
		return certErr
	}
	return staplingErr
}
