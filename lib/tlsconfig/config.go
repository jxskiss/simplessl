package tlsconfig

import (
	"crypto/tls"

	"github.com/klauspost/cpuid"
	"golang.org/x/crypto/acme"
)

func NewConfig(sslCertServerHost string, opts *Options) *tls.Config {
	client := NewClient(sslCertServerHost, opts)
	config := &tls.Config{
		GetCertificate: client.GetCertificate,

		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
			acme.ALPNProto, // enable tls-alpn challenges
		},

		// the rest recommended for modern TLS servers

		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites:             preferredDefaultCipherSuites(),
		PreferServerCipherSuites: true,
	}
	return config
}

// preferredDefaultCipherSuites returns an appropriate
// cipher suite to use depending on hardware support
// for AES-NI.
//
// See https://github.com/mholt/caddy/issues/1674
func preferredDefaultCipherSuites() []uint16 {
	if cpuid.CPU.AesNi() {
		return defaultCiphersPreferAES
	}
	return defaultCiphersPreferChaCha
}

var (
	defaultCiphersPreferAES = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	defaultCiphersPreferChaCha = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
)
