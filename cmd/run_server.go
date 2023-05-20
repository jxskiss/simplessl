package cmd

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"
	"github.com/jxskiss/gopkg/v2/zlog"
	"github.com/jxskiss/mcli"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pkgbus "github.com/jxskiss/simplessl/pkg/bus"
	"github.com/jxskiss/simplessl/pkg/config"
	"github.com/jxskiss/simplessl/pkg/utils"
	pkgsds "github.com/jxskiss/simplessl/sds"
	"github.com/jxskiss/simplessl/server"
)

// TODO: refactor RunServer into smaller parts.

func RunServer() {
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

	bus := pkgbus.NewEventBus()
	storMgr := server.NewStorageManager(cfg, stor)
	ocspMgr := server.NewOCSPManager(bus)
	selfSigned := server.NewSelfSignedManager(cfg, storMgr)
	managed := server.NewManagedCertManager(cfg, bus, storMgr, ocspMgr)
	httpSolver := server.NewHTTPAndTLSALPNSolver()
	acmeManager := server.NewACMEManager(cfg, bus, storMgr, ocspMgr, httpSolver)
	svr := server.NewServer(cfg, selfSigned, managed, acmeManager, ocspMgr, httpSolver)
	sds := pkgsds.New(bus, svr.SDSCertProvider)

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
	log.Infof("listening http traffic on %v", cfg.Listen)
	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("failed listen tcp %s, err= %v", cfg.Listen, err)
	}
	httpServer := http.Server{Handler: httpHandler}
	go func() {
		err := httpServer.Serve(lis)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed serve http service, err= %v", err)
		}
	}()

	// Run SDS grpc service.
	var grpcServer *grpc.Server
	if cfg.EnableSDS {
		log.Infof("running SDS grpc server on %v", cfg.SDSListen)
		go func() {
			lis, err := net.Listen("tcp", cfg.SDSListen)
			if err != nil {
				log.Fatalf("failed listen SDS grpc, err= %v", err)
			}

			var opts []grpc.ServerOption
			tlsConfig, err := utils.LoadLocalTLSConfig(cfg.SDSServerCert, cfg.SDSServerKey, cfg.SDSCACert)
			if err != nil {
				log.Fatalf("failed load grpc credentials, err= %v", err)
			}
			opts = append(opts,
				grpc.Creds(credentials.NewTLS(tlsConfig)),

				// TODO
				//grpc.UnaryInterceptor(),
				//grpc.StreamInterceptor(),
			)
			grpcServer = grpc.NewServer(opts...)
			sds.Register(grpcServer)
			err = grpcServer.Serve(lis)
			if err != nil && err != grpc.ErrServerStopped {
				log.Fatalf("failed serve secure SDS grpc, err= %v", err)
			}
		}()
	}

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
	exitWg := new(sync.WaitGroup)
	waitCh := make(chan struct{})

	exitWg.Add(1)
	go func() {
		err := httpServer.Shutdown(ctx)
		if err == nil {
			log.Info("shutdown http server gracefully")
		} else {
			log.Errorf("failed gracefully shutdown http server, err= %v", err)
		}
		exitWg.Done()
	}()
	if grpcServer != nil {
		exitWg.Add(1)
		go func() {
			grpcServer.GracefulStop()
			exitWg.Done()
		}()
	}
	go func() {
		exitWg.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
		// pass
	case <-ctx.Done():
		log.Errorf("waiting server gracefully shutdown timeout")
	}
}
