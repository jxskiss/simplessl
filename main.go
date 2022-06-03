package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"
	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/jxskiss/mcli"

	"github.com/jxskiss/ssl-cert-server/pkg/lego"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
	"github.com/jxskiss/ssl-cert-server/server"
)

const VERSION = "0.5.0"

func main() {
	zlog.SetDevelopment()
	defer zlog.Sync()

	if len(os.Args) < 2 {
		os.Args = append(os.Args, "run")
	} else if strings.HasPrefix(os.Args[1], "-") &&
		os.Args[1] != "-h" {
		modifiedArgs := os.Args[:1:1]
		modifiedArgs = append(modifiedArgs, "run")
		modifiedArgs = append(modifiedArgs, os.Args[1:]...)
		os.Args = modifiedArgs
	}

	mcli.AddHelp()
	mcli.Add("run", cmdRunServer, "Run certificate server")
	mcli.Add("generate-self-signed", cmdGenerateSelfSignedCertificate, "Generate self-signed certificate")
	mcli.Add("version", cmdPrintVersion, "Print version information")
	mcli.Run()
}

func cmdPrintVersion() {
	gitRevision := "unknown"
	buildInfo, ok := debug.ReadBuildInfo()
	if ok {
		for _, setting := range buildInfo.Settings {
			if setting.Key == "vcs.revision" {
				gitRevision = setting.Value
				if len(gitRevision) > 12 {
					gitRevision = gitRevision[:12]
				}
			}
		}
	}
	fmt.Printf("ssl-cert-server v%s-%s\n", VERSION, gitRevision)
}

func initConfigAndCreateServer(opts server.Opts) *server.Server {
	server.InitConfig(opts)
	svr := server.NewServer()
	return svr
}

func cmdRunServer() {
	var opts server.Opts
	mcli.Parse(&opts)

	cfg := server.Cfg
	svr := initConfigAndCreateServer(opts)

	// Setup Lego application.
	if len(cfg.Wildcard.Certificates) > 0 {
		setupLegoApp(svr.AutocertMgr)
	}

	mux := http.NewServeMux()
	svr.AutocertMgr.BuildRoutes(mux)

	// Graceful restarts.
	upg, err := tableflip.New(tableflip.Options{
		UpgradeTimeout: time.Minute,
		PIDFile:        cfg.PIDFile,
	})
	if err != nil {
		zlog.Fatalf("server: failed init upgrader: %v", err)
	}
	defer upg.Stop()

	// Do an upgrade on SIGHUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				zlog.Errorf("server: failed do upgrade: %v", err)
			}
		}
	}()

	// Listen must be called before Ready
	ln, err := upg.Listen("tcp", cfg.Listen)
	if err != nil {
		zlog.Fatalf("server: failed listen: %v", err)
	}
	httpServer := http.Server{Handler: mux}
	go func() {
		zlog.Infof("server: listening on http://%v", cfg.Listen)
		err := httpServer.Serve(ln)
		if err != http.ErrServerClosed {
			zlog.Fatalf("server: stopped unexpectedly: %v", err)
		}
	}()

	if err := upg.Ready(); err != nil {
		zlog.Fatalf("server: upgrader not ready: %v", err)
	}

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-upg.Exit():
		zlog.Infof("server: received exit signal from upgrader")
	case <-stop:
		zlog.Infof("server: received stop signal from system")
	}

	// Graceful shutdown the old process.
	// Make sure to set a deadline on exiting the process after upg.Exit()
	// is closed. No new upgrades can be performed if the parent doesn't exit.
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	err = httpServer.Shutdown(ctx)
	if err == nil {
		zlog.Infof("server: shutdown gracefully")
	} else {
		zlog.Warnf("server: failed graceful shutdown: %v", err)
	}
}

func setupLegoApp(mgr *server.Manager) {
	cfg := server.Cfg
	ctx := context.Background()
	acmeAccount, privKey, err := mgr.GetACMEAccount(ctx)
	if err != nil {
		zlog.Fatalf("server: failed get ACME account: %v", err)
	}
	legoAcc, err := lego.FromACMEAccount(cfg.LetsEncrypt.Email, acmeAccount, privKey)
	if err != nil {
		zlog.Fatalf("server: failed convert ACME account: %v", err)
	}
	err = lego.SetupApp(cfg.Wildcard.LegoDataPath, legoAcc)
	if err != nil {
		zlog.Fatalf("server: failed setup Lego app: %v", err)
	}
}

func cmdGenerateSelfSignedCertificate() {
	var opts struct {
		ValidDays     int      `cli:"--valid-days, number of days the cert is valid for" default:"365"`
		Out           string   `cli:"--out, output single file contains both private key and certificate" default:"./self_signed"`
		CertOut       string   `cli:"--cert-out, output certificate file" default:"./self_signed.cert"`
		KeyOut        string   `cli:"--key-out, output private key file" default:"./self_signed.key"`
		Organizations []string `cli:"--organization, certificate organization (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	if len(opts.Organizations) == 0 {
		opts.Organizations = server.DefaultSelfSignedOrganization
	}

	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(opts.ValidDays, opts.Organizations)
	if err != nil {
		zlog.Fatalf("failed create self-signed certificate: %v", err)
	}
	err = utils.WriteFile(opts.KeyOut, privKeyPEM, 0600)
	if err == nil {
		err = utils.WriteFile(opts.CertOut, certPEM, 0600)
	}
	if err == nil {
		outData := append(privKeyPEM, certPEM...)
		err = utils.WriteFile(opts.Out, outData, 0600)
	}
	if err != nil {
		zlog.Fatalf("failed write self-signed certificate files: %v", err)
	}
}
