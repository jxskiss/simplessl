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

	certExpire     int64
	staplingExpire int64
}

type Client struct {
	host  string
	cache sync.Map
}

func NewClient(sslCertServerHost string) *Client {
	if !strings.HasPrefix(sslCertServerHost, "http://") {
		sslCertServerHost = "http://" + sslCertServerHost
	}
	sslCertServerHost = strings.TrimSuffix(sslCertServerHost, "/")
	client := &Client{
		host: sslCertServerHost,
	}
	go client.Watch()
	return client
}

func (c *Client) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("missing server name")
	}
	if !strings.Contains(strings.Trim(name, "."), ".") {
		return nil, errors.New("server name component count invalid")
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
		return nil, errors.New("server name contains invalid character")
	}

	cert, err := c.getCertificate(name)
	return cert, err
}

func (c *Client) getCertificate(domainName string) (*tls.Certificate, error) {
	cacheKey := domainName
	cacheVal, ok := c.cache.Load(cacheKey)
	if ok {
		cached := cacheVal.(*cacheItem)
		return cached.cert, nil
	}

	// first request for a new domain, give it a long time
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cert, certExpire, err := c.requestCertificate(ctx, domainName)
	if err != nil {
		return nil, err
	}

	// OCSP stapling is optional
	// don't fail the server request in case of unavailable
	stapling, staplingExpire, err := c.requestStapling(ctx, domainName)
	if err != nil {
		log.Printf("[WARN] failed request OCSP stapling: %v", err)
	}

	cert.OCSPStaple = stapling
	cacheItem := &cacheItem{
		cert:           cert,
		certExpire:     certExpire,
		staplingExpire: staplingExpire,
	}
	c.cache.Store(cacheKey, cacheItem)
	return cacheItem.cert, nil
}

func (c *Client) requestCertificate(ctx context.Context, domainName string) (
	certificate *tls.Certificate, expireAt int64, err error,
) {
	var response struct {
		Cert     string `json:"cert"`
		PKey     string `json:"pkey"`
		ExpireAt int64  `json:"expire_at"` // seconds since epoch
		TTL      int64  `json:"ttl"`       // in seconds
	}

	apiPath := c.host + "/cert/" + domainName
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
		err = fmt.Errorf("request certificate: bad http status: %d", resp.StatusCode)
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
	expireAt = time.Now().Unix() + response.TTL
	return
}

func (c *Client) requestStapling(ctx context.Context, domainName string) (
	stapling []byte, expireAt int64, err error,
) {
	apiPath := c.host + "/ocsp/" + domainName
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
		err = fmt.Errorf("request stapling: bad http status: %d", resp.StatusCode)
		return
	}
	stapling, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	ttl, _ := strconv.ParseInt(resp.Header.Get("X-TTL"), 10, 64)
	if ttl == 0 {
		ttl = 600
	}
	expireAt = time.Now().Unix() + ttl
	return
}

func (c *Client) Watch() {
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
		if citem.certExpire > now && citem.staplingExpire > now {
			continue
		}

		// certificate or OCSP stapling comes to TTL, do refresh

		// shallow copy the certificate to avoid data race
		// we may change the OCSPStaple below
		cert := *citem.cert

		newCacheItem := &cacheItem{
			cert:           &cert,
			certExpire:     citem.certExpire,
			staplingExpire: citem.staplingExpire,
		}

		ctx, cancel := context.WithTimeout(bgctx, time.Second)
		if newCacheItem.certExpire <= now {
			newCert, expireAt, err := c.requestCertificate(ctx, domainName)
			if err != nil {
				log.Printf("[WARN] failed refresh certificate: %s: %v", domainName, err)
				if certErr == nil {
					certErr = err
				}
			} else {
				newCacheItem.cert = newCert
				newCacheItem.certExpire = expireAt
			}
		}
		if newCacheItem.staplingExpire <= now {
			newStapling, expireAt, err := c.requestStapling(ctx, domainName)
			if err != nil {
				log.Printf("[WARN] failed refresh OCSP stapling: %s: %v", domainName, err)
				if staplingErr == nil {
					staplingErr = err
				}
			} else {
				newCacheItem.cert.OCSPStaple = newStapling
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
