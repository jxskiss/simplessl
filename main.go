package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"
	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/jxskiss/mcli"

	"github.com/jxskiss/ssl-cert-server/pkg/config"
	"github.com/jxskiss/ssl-cert-server/pkg/utils"
	"github.com/jxskiss/ssl-cert-server/server"
)

const VERSION = "0.6.2"

func main() {
	zlog.SetDevelopment()
	defer zlog.Sync()

	mcli.AddHelp()
	mcli.Add("run", cmdRunServer, "Run certificate server")
	mcli.Add("generate-self-signed", cmdGenerateSelfSignedCertificate, "Generate self-signed certificate")
	mcli.Add("version", cmdPrintVersion, "Print version information")
	mcli.Run()
}

func cmdRunServer() {
	var args struct {
		ConfigFile string `cli:"-c, --config, configuration filename" default:"./conf.yaml"`
	}
	mcli.Parse(&args)

	log := zlog.Named("main").Sugar()

	cfg, err := config.LoadConfig(args.ConfigFile)
	if err != nil {
		log.Fatalf("failed load config, err= %v", err)
	}
	var stor server.Storage
	switch cfg.Storage.Type {
	case server.StorageTypeDirCache:
		stor = server.NewDirCache(cfg.Storage.DirCache)
	case server.StorageTypeRedis:
		stor, err = server.NewRedisCache(cfg.Storage.Redis)
		if err != nil {
			log.Fatalf("failed init redis storage, err= %v", err)
		}
	default:
		log.Fatalf("unknown storage type: %v", cfg.Storage.Type)
	}

	storMgr := server.NewStorageManager(cfg, stor)
	ocspMgr := server.NewOCSPManager()
	selfSigned := server.NewSelfSignedManager(cfg, storMgr)
	managed := server.NewManagedCertManager(cfg, storMgr, ocspMgr)
	httpSolver := server.NewHTTPAndTLSALPNSolver()
	acmeManager := server.NewACMEManager(cfg, storMgr, ocspMgr, httpSolver)
	svr := server.NewServer(cfg, selfSigned, managed, acmeManager, ocspMgr, httpSolver)

	httpHandler, err := server.NewMux(svr)
	if err != nil {
		log.Fatalf("failed init server http handler, err= %v", err)
	}

	// Graceful restarts.
	upg, err := tableflip.New(tableflip.Options{
		UpgradeTimeout: time.Minute,
		PIDFile:        cfg.PIDFile,
	})
	if err != nil {
		log.Fatalf("failed init upgrader, err= %v", err)
	}
	defer upg.Stop()

	// Do an upgrade on SIGHUP.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				log.Errorf("failed do upgrade, err= %v", err)
			}
		}
	}()

	// Listen must be called before upg.Ready.
	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("failed listen tcp %s, err= %v", cfg.Listen, err)
	}
	log.Infof("listening on %v", cfg.Listen)
	httpServer := http.Server{Handler: httpHandler}
	go func() {
		err := httpServer.Serve(lis)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed serve http, err= %v", err)
		}
	}()

	if err := upg.Ready(); err != nil {
		log.Fatalf("upgrader not ready, err= %v", err)
	}

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-upg.Exit():
		log.Info("received exit signal from upgrader")
	case <-stop:
		log.Info("received stop signal from system")
	}

	// Graceful shutdown the old process.
	// Make sure to set a deadline on exiting the process after upg.Exit()
	// is closed. No new upgrades can be performed if the parent doesn't exit.
	ctx, _ := context.WithTimeout(context.Background(), time.Minute)
	err = httpServer.Shutdown(ctx)
	if err == nil {
		log.Info("shutdown gracefully")
	} else {
		log.Errorf("failed graceful shutdown, err= %v", err)
	}
}

func cmdGenerateSelfSignedCertificate() {
	var opts struct {
		Days          int      `cli:"--days, number of days the cert is valid for" default:"365"`
		BundleOut     string   `cli:"--bundle-out, output single file contains both private key and certificate" default:"./self_signed"`
		CertOut       string   `cli:"--cert-out, output certificate file" default:"./self_signed.crt"`
		KeyOut        string   `cli:"--key-out, output private key file" default:"./self_signed.key"`
		Organizations []string `cli:"--organization, certificate organization (may be given multiple times)"`
	}
	mcli.Parse(&opts)

	log := zlog.Named("main").Sugar()

	if len(opts.Organizations) == 0 {
		opts.Organizations = config.DefaultSelfSignedOrganizations
	}

	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(opts.Days, opts.Organizations)
	if err != nil {
		log.Fatalf("failed create self-signed certificate: %v", err)
	}
	err = utils.WriteFile(opts.KeyOut, privKeyPEM, 0600)
	if err == nil {
		err = utils.WriteFile(opts.CertOut, certPEM, 0600)
	}
	if err == nil {
		outData := append(privKeyPEM, certPEM...)
		err = utils.WriteFile(opts.BundleOut, outData, 0600)
	}
	if err != nil {
		log.Fatalf("failed write self-signed certificate files: %v", err)
	}
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
