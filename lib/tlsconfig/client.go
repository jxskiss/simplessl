package tlsconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"

	"github.com/jxskiss/ssl-cert-server/lib/tlsconfig/proto"
)

// ALPNProto is the ALPN protocol name used by a CA server when validating
// tls-alpn-01 challenges.
const ALPNProto = "acme-tls/1"

type cacheCertificate struct {
	*proto.Certificate

	cert *tls.Certificate

	certExpire  int64
	certRefresh int64

	staplingExpire  int64
	staplingRefresh int64
}

type Client struct {
	serverHost string
	opts       Options
	hostPolicy func(name string) error

	// copy-on-write map
	cacheMu sync.Mutex
	cache   atomic.Value // map[string]*cacheCertificate
}

func NewClient(sslCertServerHost string, opts Options) *Client {
	if opts.ErrorLog == nil {
		opts.ErrorLog = log.Printf
	}
	if !strings.HasPrefix(sslCertServerHost, "http://") {
		sslCertServerHost = "http://" + sslCertServerHost
	}
	sslCertServerHost = strings.TrimSuffix(sslCertServerHost, "/")
	client := &Client{
		serverHost: sslCertServerHost,
		opts:       opts,
	}
	client.cache.Store(make(map[string]*cacheCertificate))
	go client.watch()

	// make host policy
	client.hostPolicy = opts.makeHostPolicy()

	// preload certificates for pre-defined domain names
	client.preloadDomains(opts.PreloadAsync, opts.PreloadDomains...)

	return client
}

func (c *Client) getCacheMap() map[string]*cacheCertificate {
	return c.cache.Load().(map[string]*cacheCertificate)
}

func (c *Client) getCachedCert(key string) *cacheCertificate {
	return c.getCacheMap()[key]
}

func (c *Client) addCachedCert(key string, cert *cacheCertificate) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	oldCache := c.cache.Load().(map[string]*cacheCertificate)
	newCache := make(map[string]*cacheCertificate, len(oldCache)+1)
	for k, v := range oldCache {
		newCache[k] = v
	}
	newCache[key] = cert
	c.cache.Store(newCache)
}

func (c *Client) GetTLSCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName

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

	var cert *tls.Certificate
	var isALPN01 = len(hello.SupportedProtos) == 1 && hello.SupportedProtos[0] == ALPNProto
	if isALPN01 {
		cert, err = c.getALPN01Certificate(name)
	} else {
		cert, err = c.getCertificate(name)
	}
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: get certificate: %v", err)
	}
	return cert, err
}

func (c *Client) getCertificate(domainName string) (*tls.Certificate, error) {
	cacheKey := domainName
	cacheCert := c.getCachedCert(cacheKey)
	if cacheCert != nil {
		now := time.Now().Unix()
		// in case the cached OCSP stapling is going to expire, abandon it
		if cacheCert.staplingExpire > 0 && cacheCert.staplingExpire <= now-60 {
			copyCert := *cacheCert.cert
			copyCert.OCSPStaple = nil
			newCacheCert := &cacheCertificate{
				Certificate:     cacheCert.Certificate,
				cert:            &copyCert,
				certExpire:      cacheCert.certExpire,
				certRefresh:     cacheCert.certRefresh,
				staplingExpire:  0,
				staplingRefresh: 0,
			}
			c.addCachedCert(cacheKey, newCacheCert)
			cacheCert = newCacheCert
		}
		return cacheCert.cert, nil
	}

	// first request for a new domain, give it a long time
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cacheCert, err := c.requestCertificate(ctx, domainName, false)
	if err != nil {
		return nil, err
	}

	// If OCSP is enabled, get it.
	// And since OCSP stapling is optional, we don't fail the server request
	// in case of OCSP stapling unavailable.
	if !c.opts.DisableStapling && cacheCert.HasOcspStapling {
		stapling, staplingExpire, staplingRefresh, err := c.requestStapling(ctx, domainName, cacheCert.Fp)
		if err != nil {
			c.opts.ErrorLog("[WARN] tlsconfig: failed request OCSP stapling: domain= %s err= %v", domainName, err)
		} else {
			cacheCert.cert.OCSPStaple = stapling
			cacheCert.staplingExpire = staplingExpire
			cacheCert.staplingRefresh = staplingRefresh
		}
		// ensure OCSP stapling loaded as soon as possible
		if len(cacheCert.cert.OCSPStaple) == 0 {
			go c.eagerPullOCSPStapling(domainName)
		}
	}

	c.addCachedCert(cacheKey, cacheCert)
	return cacheCert.cert, nil
}

func (c *Client) getALPN01Certificate(domainName string) (*tls.Certificate, error) {
	ctx := context.Background()
	respCert, err := c.requestCertificate(ctx, domainName, true)
	if err != nil {
		return nil, err
	}
	return respCert.cert, nil
}

func (c *Client) eagerPullOCSPStapling(domainName string) {
	var sleep = 10 * time.Millisecond
	for i := 0; true; i++ {
		sleep *= 2
		if sleep >= 30*time.Second {
			break
		}
		time.Sleep(sleep)

		cacheCert := c.getCachedCert(domainName)
		if cacheCert == nil { // this shall not happen
			continue
		}
		if len(cacheCert.cert.OCSPStaple) > 0 {
			break
		}
		newCacheCert, _, _ := c.refreshDomainCertificate(domainName, cacheCert)
		if len(newCacheCert.cert.OCSPStaple) > 0 {
			c.addCachedCert(domainName, newCacheCert)
			break
		}
	}
}

func (c *Client) RequestCertificate(ctx context.Context, req *proto.GetCertificateRequest) (resp *proto.GetCertificateResponse, err error) {
	apiURL := c.serverHost + "/sslcertserver.CertServer/GetCertificate"
	data, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		err = proto.DecodeError(httpResp.StatusCode, httpResp.Body)
		return nil, err
	}

	resp = &proto.GetCertificateResponse{}
	err = json.NewDecoder(httpResp.Body).Decode(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) requestCertificate(ctx context.Context, domainName string, isALPN01 bool) (
	cacheCert *cacheCertificate, err error,
) {
	req := &proto.GetCertificateRequest{
		Domain:           domainName,
		IsAlpn:           isALPN01,
		WantOcspStapling: false,
	}
	resp, err := c.RequestCertificate(ctx, req)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair([]byte(resp.Cert.PubKey), []byte(resp.Cert.PrivKey))
	if err != nil {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	cert.Leaf = leaf

	cacheCert = &cacheCertificate{
		Certificate: resp.Cert,
		cert:        &cert,
		certExpire:  resp.Cert.NotAfterSec,
		certRefresh: time.Now().Unix() + resp.Cert.TtlSec,
	}
	return
}

func (c *Client) requestStapling(ctx context.Context, domainName string, fingerprint string) (
	stapling []byte, expireAt, refreshAt int64, err error,
) {
	apiURL := c.serverHost
	data, _ := json.Marshal(&proto.GetOCSPStaplingRequest{
		Domain:      domainName,
		Fingerprint: fingerprint,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		err = proto.DecodeError(httpResp.StatusCode, httpResp.Body)
		if errCode, ok := err.(*proto.ErrorCode); ok {
			if errCode.Code == proto.CodeNoContent {
				return nil, 0, 0, nil
			}
		}
		return
	}
	protoResp := &proto.GetOCSPStaplingResponse{}
	err = json.NewDecoder(httpResp.Body).Decode(protoResp)
	if err != nil {
		return
	}
	ocspStapling := protoResp.OcspStapling
	if ocspStapling != nil {
		stapling = ocspStapling.Raw
		expireAt = ocspStapling.NextUpdateSec
		refreshAt = time.Now().Unix() + ocspStapling.TtlSec
	}
	return
}

func (c *Client) watch() {
	ticker := time.Minute
	for range time.Tick(ticker) {

		// in case of error, retry 2 times
		for i := 1; i < 4; i++ {
			cached := c.getCacheMap()
			err := c.refresh(cached)
			if err == nil {
				break
			}
			time.Sleep(time.Duration(i) * time.Second)
		}
	}
}

func (c *Client) refresh(cached map[string]*cacheCertificate) error {
	for domainName, cacheCert := range cached {
		newCacheCert, updated, err := c.refreshDomainCertificate(domainName, cacheCert)
		if updated {
			c.addCachedCert(domainName, newCacheCert)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) refreshDomainCertificate(domainName string, cacheCert *cacheCertificate) (
	newCacheCert *cacheCertificate, updated bool, err error,
) {
	now := time.Now().Unix()
	if cacheCert.certRefresh > now && cacheCert.staplingRefresh > now {
		return cacheCert, false, nil
	}

	// certificate or OCSP stapling comes to TTL, do refresh

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// shallow copy the certificate to avoid data race
	// we may change the OCSPStaple below
	copyCert := *cacheCert.cert
	newCacheCert = &cacheCertificate{
		Certificate:     cacheCert.Certificate,
		cert:            &copyCert,
		certRefresh:     cacheCert.certRefresh,
		certExpire:      cacheCert.certExpire,
		staplingRefresh: cacheCert.staplingRefresh,
		staplingExpire:  cacheCert.staplingExpire,
	}

	if newCacheCert.certRefresh <= now {
		respCert, err := c.requestCertificate(ctx, domainName, false)
		if err != nil {
			c.opts.ErrorLog("[WARN] tlsconfig: failed refresh certificate: domain= %s err= %v", domainName, err)
			return newCacheCert, updated, err
		}
		updated = true
		newCacheCert.certExpire = respCert.certExpire
		newCacheCert.certRefresh = respCert.certRefresh

		// certificate renewed or type changed
		// save new cert and drop the old OCSP stapling information
		if newCacheCert.Type != respCert.Type || newCacheCert.Fp != respCert.Fp {
			newCacheCert.Certificate = respCert.Certificate
			newCacheCert.cert = respCert.cert
			newCacheCert.staplingExpire = 0
			newCacheCert.staplingRefresh = 0
		}
	}

	if !c.opts.DisableStapling && newCacheCert.HasOcspStapling &&
		newCacheCert.staplingRefresh <= now {
		newStapling, expireAt, refreshAt, err := c.requestStapling(ctx, domainName, newCacheCert.Fp)
		if err != nil {
			c.opts.ErrorLog("[WARN] tlsconfig: failed refresh OCSP stapling: domain= %s err= %v", domainName, err)
			// if the OCSP stapling is going to expire, abandon it
			if newCacheCert.staplingExpire-now < 60 {
				updated = true
				newCacheCert.cert.OCSPStaple = nil
				newCacheCert.staplingExpire = 0
				newCacheCert.staplingRefresh = 0
			}
			return newCacheCert, updated, err
		} else if expireAt-now > 60 {
			updated = true
			newCacheCert.cert.OCSPStaple = newStapling
			newCacheCert.staplingExpire = expireAt
			newCacheCert.staplingRefresh = refreshAt
		}
	}

	return newCacheCert, updated, nil
}
