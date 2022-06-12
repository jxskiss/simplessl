package lego

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/cmd"
	"github.com/go-acme/lego/v4/log"
	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/net/idna"

	"github.com/jxskiss/ssl-cert-server/pkg/utils"
)

var app *cli.App

func SetupApp(dataPath string, acc *Account) error {
	if dataPath == "" {
		panic("dataPath must be specified")
	}

	// Setup custom logger.
	log.Logger = newLogger()

	// Save account data to storage.
	err := acc.Save(dataPath)
	if err != nil {
		return err
	}

	app = cli.NewApp()
	app.Before = cmd.Before
	app.Flags = cmd.CreateFlags(dataPath)
	app.Commands = cmd.CreateCommands()
	return nil
}

func IssueCertificate(args *CertArgs) (*Certificate, error) {
	err := args.execRunCommand()
	if err != nil {
		return nil, fmt.Errorf("run command 'lego new': %w", err)
	}

	cert := &Certificate{
		RootDomain: args.RootDomain,
		Domains:    args.Domains,
	}
	err = cert.Load(args.DataPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	return cert, nil
}

func RenewCertificate(args *CertArgs, cert *Certificate) (*Certificate, error) {
	err := cert.Save(args.DataPath)
	if err != nil {
		return nil, fmt.Errorf("save certificate: %w", err)
	}

	err = args.execRenewCommand()
	if err != nil {
		return nil, fmt.Errorf("run command 'lego renew': %w", err)
	}

	newCert := &Certificate{
		RootDomain: args.RootDomain,
		Domains:    args.Domains,
	}
	err = newCert.Load(args.DataPath)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	return newCert, nil
}

// sanitizedDomain Make sure no funny chars are in the cert names (like wildcards ;)).
func sanitizedDomain(domain string) string {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		zlog.Fatalf("cannot sanitize domain: %skip2", domain)
	}
	return safe
}

type CertArgs struct {
	DataPath string

	Email      string
	Server     string
	DnsCode    string
	Env        map[string]string
	RootDomain string
	Domains    []string
	Hook       string

	RenewOpts struct {
		ReuseKey bool
		Days     int
	}
}

/*
NAME:
   lego run - Register an account, then create and install a certificate

USAGE:
   lego run [command options] [arguments...]

OPTIONS:
   --no-bundle                               Do not create a certificate bundle by adding the issuers certificate to the new certificate. (default: false)
   --must-staple                             Include the OCSP must staple TLS extension in the CSR and generated certificate. Only works if the CSR is generated by lego. (default: false)
   --run-hook value                          Define a hook. The hook is executed when the certificates are effectively created.
   --preferred-chain value                   If the CA offers multiple certificate chains, prefer the chain with an issuer matching this Subject Common Name. If no match, the default offered chain will be used.
   --always-deactivate-authorizations value  Force the authorizations to be relinquished even if the certificate request was successful.
   --help, -h                                show help (default: false)

*/

func (p *CertArgs) execRunCommand() (err error) {
	args := []string{
		"lego",
		"--accept-tos",
		"--server", p.Server,
		"--email", p.Email,
		"--dns", p.DnsCode,
	}
	for _, dom := range p.Domains {
		args = append(args, "--domains", dom)
	}
	runArgs := []string{"run"}
	if p.Hook != "" {
		runArgs = append(runArgs, "--run-hook", p.Hook)
	}
	args = append(args, runArgs...)

	for k, v := range p.Env {
		err = os.Setenv(k, v)
		if err != nil {
			return fmt.Errorf("cannot set env %q: %w", k, err)
		}
	}
	err = app.Run(args)
	return err
}

/*
NAME:
   lego renew - Renew a certificate

USAGE:
   lego renew [command options] [arguments...]

OPTIONS:
   --days value                              The number of days left on a certificate to renew it. (default: 30)
   --reuse-key                               Used to indicate you want to reuse your current private key for the new certificate. (default: false)
   --no-bundle                               Do not create a certificate bundle by adding the issuers certificate to the new certificate. (default: false)
   --must-staple                             Include the OCSP must staple TLS extension in the CSR and generated certificate. Only works if the CSR is generated by lego. (default: false)
   --renew-hook value                        Define a hook. The hook is executed only when the certificates are effectively renewed.
   --preferred-chain value                   If the CA offers multiple certificate chains, prefer the chain with an issuer matching this Subject Common Name. If no match, the default offered chain will be used.
   --always-deactivate-authorizations value  Force the authorizations to be relinquished even if the certificate request was successful.
   --help, -h                                show help (default: false)

*/

func (p *CertArgs) execRenewCommand() (err error) {
	args := []string{
		"lego",
		"--accept-tos",
		"--server", p.Server,
		"--email", p.Email,
		"--dns", p.DnsCode,
	}
	for _, dom := range p.Domains {
		args = append(args, "--domains", dom)
	}
	renewArgs := []string{"renew"}
	renewArgs = append(renewArgs, "--days", fmt.Sprint(p.RenewOpts.Days))
	if p.RenewOpts.ReuseKey {
		renewArgs = append(renewArgs, "--reuse-key")
	}
	if p.Hook != "" {
		renewArgs = append(renewArgs, "--renew-hook", p.Hook)
	}
	args = append(args, renewArgs...)

	for k, v := range p.Env {
		err = os.Setenv(k, v)
		if err != nil {
			return fmt.Errorf("cannot set env %q: %w", k, err)
		}
	}
	err = app.Run(args)
	return err
}

func writeFile(name string, data []byte, perm os.FileMode) error {
	return utils.WriteFile(name, data, perm)
}

func newLogger() *wrapLogger {
	l := zlog.L().Named("lego")
	skip2 := l.WithOptions(zap.AddCallerSkip(2)).Sugar()
	skip3 := l.WithOptions(zap.AddCallerSkip(3)).Sugar()
	return &wrapLogger{
		skip2: skip2,
		skip3: skip3,
	}
}

type wrapLogger struct {
	skip2 *zap.SugaredLogger
	skip3 *zap.SugaredLogger
}

func (w *wrapLogger) Fatal(args ...interface{}) {
	w.skip2.Fatal(args...)
}

func (w *wrapLogger) Fatalln(args ...interface{}) {
	w.skip2.Fatal(args...)
}

func (w *wrapLogger) Fatalf(format string, args ...interface{}) {
	w.skip2.Fatalf(format, args...)
}

func (w *wrapLogger) Print(args ...interface{}) {
	w.skip2.Info(args...)
}

func (w *wrapLogger) Println(args ...interface{}) {
	w.skip2.Info(args...)
}

func (w *wrapLogger) Printf(format string, args ...interface{}) {
	if strings.HasPrefix(format, "[INFO] ") {
		w.skip3.Infof(format[7:], args...)
		return
	}
	if strings.HasPrefix(format, "[WARN] ") {
		w.skip3.Warnf(format[7:], args...)
		return
	}
	w.skip2.Infof(format, args...)
}
