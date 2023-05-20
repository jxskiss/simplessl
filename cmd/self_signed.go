package cmd

import (
	"os"

	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/jxskiss/mcli"

	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
	"github.com/jxskiss/ssl-cert-server/server"
)

func GenerateSelfSignedCertificate() {
	var opts struct {
		Days          int      `cli:"-d, --days, number of days the cert is valid for" default:"3650"`
		BundleOut     string   `cli:"--bundle-out, output single file contains both private key and certificate" default:"./self_signed.bundle"`
		CertOut       string   `cli:"--cert-out, output certificate file" default:"./self_signed.cert"`
		KeyOut        string   `cli:"--key-out, output private key file" default:"./self_signed.key"`
		Organizations []string `cli:"--organization, certificate organization (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	log := zlog.S()
	if len(opts.Organizations) == 0 {
		opts.Organizations = config.DefaultSelfSignedOrganizations
	}
	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(&server.GenCertArgs{
		ValidDays:     opts.Days,
		Organizations: opts.Organizations,
		Type:          "ca",
	})
	if err != nil {
		log.Fatalf("failed create self-signed certificate: %v", err)
	}
	err = writeCertFiles(opts.BundleOut, opts.CertOut, opts.KeyOut, certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("failed write self-signed certificate files: %v", err)
	}
}

func SelfSignCACertificate() {
	var opts struct {
		Days          int      `cli:"-d, --days, number of days the cert is valid for" default:"3650"`
		BundleOut     string   `cli:"--bundle-out, output single file contains both private key and certificate" default:"./secret-dir/ca.bundle"`
		CertOut       string   `cli:"--cert-out, output certificate file" default:"./secret-dir/ca.cert"`
		KeyOut        string   `cli:"--key-out, output private key file" default:"./secret-dir/ca.key"`
		Organizations []string `cli:"--organization, certificate organization (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	log := zlog.S()
	if len(opts.Organizations) == 0 {
		opts.Organizations = config.DefaultSelfSignedOrganizations
	}
	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(&server.GenCertArgs{
		ValidDays:     opts.Days,
		Organizations: opts.Organizations,
		Type:          "ca",
	})
	if err != nil {
		log.Fatalf("failed create self-signed CA certificate: %v", err)
	}
	err = writeCertFiles(opts.BundleOut, opts.CertOut, opts.KeyOut, certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("failed write self-signed CA certificate files: %v", err)
	}
}

var (
	defaultClientHosts = []string{
		"ssl-cert-server.internal",
		"client.ssl-cert-server.internal",
		"sds-client.ssl-cert-server.internal",
	}
	defaultServerHosts = []string{
		"ssl-cert-server.internal",
		"server.ssl-cert-server.internal",
		"sds-server.ssl-cert-server.internal",
	}
)

func SelfSignSDSClientCertificate() {
	var opts struct {
		Days     int      `cli:"-d, --days, number of days the cert is valid for" default:"3650"`
		CABundle string   `cli:"--ca-bundle, the CA certificate bundle file" default:"./secret-dir/ca.bundle"`
		CertOut  string   `cli:"--cert-out, output certificate file" default:"./secret-dir/sds-client.cert"`
		KeyOut   string   `cli:"--key-out, output private key file" default:"./secret-dir/sds-client.key"`
		Hosts    []string `cli:"--host, certificate host (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	log := zlog.S()
	if len(opts.Hosts) == 0 {
		opts.Hosts = defaultClientHosts
	}
	caData, err := os.ReadFile(opts.CABundle)
	if err != nil {
		log.Fatalf("failed read CA certificate: %v", err)
	}
	caCert, _, _, err := utils.ParseCertificate(caData)
	if err != nil {
		log.Fatalf("failed parse CA certificate: %v", err)
	}
	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(&server.GenCertArgs{
		CA:        caCert,
		ValidDays: opts.Days,
		Hosts:     opts.Hosts,
		Type:      "client",
	})
	if err != nil {
		log.Fatalf("failed create SDS client certificate: %v", err)
	}
	err = writeCertFiles("", opts.CertOut, opts.KeyOut, certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("failed write SDS certificate files: %v", err)
	}
}

func SelfSignSDSServerCertificate() {
	var opts struct {
		Days     int      `cli:"-d, --days, number of days the cert is valid for" default:"3650"`
		CABundle string   `cli:"--ca-bundle, the CA certificate bundle file" default:"./secret-dir/ca.bundle"`
		CertOut  string   `cli:"--cert-out, output certificate file" default:"./secret-dir/sds-server.cert"`
		KeyOut   string   `cli:"--key-out, output private key file" default:"./secret-dir/sds-server.key"`
		Hosts    []string `cli:"--host, certificate host (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	log := zlog.S()
	if len(opts.Hosts) == 0 {
		opts.Hosts = defaultServerHosts
	}
	caData, err := os.ReadFile(opts.CABundle)
	if err != nil {
		log.Fatalf("failed read CA certificate: %v", err)
	}
	caCert, _, _, err := utils.ParseCertificate(caData)
	if err != nil {
		log.Fatalf("failed parse CA certificate: %v", err)
	}
	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(&server.GenCertArgs{
		CA:        caCert,
		ValidDays: opts.Days,
		Hosts:     opts.Hosts,
		Type:      "server",
	})
	if err != nil {
		log.Fatalf("failed create SDS server certificate: %v", err)
	}
	err = writeCertFiles("", opts.CertOut, opts.KeyOut, certPEM, privKeyPEM)
	if err != nil {
		log.Fatalf("failed write SDS certificate files: %v", err)
	}
}

func writeCertFiles(
	bundleOut, certOut, keyOut string,
	certPEM, keyPEM []byte,
) (err error) {
	err = utils.WriteFile(keyOut, keyPEM, 0600)
	if err == nil {
		err = utils.WriteFile(certOut, certPEM, 0600)
	}
	if err == nil && bundleOut != "" {
		outData := append(keyPEM, certPEM...)
		err = utils.WriteFile(bundleOut, outData, 0600)
	}
	return err
}
