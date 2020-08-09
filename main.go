package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	defer flushLogs()
	flag.Usage = PrintUsage
	if len(os.Args) >= 2 && os.Args[1] == generateSelfSignedCertSubCommand {
		cmdGenerateSelfSignedCertificate()
		return
	}
	initFlags()
	if Flags.ShowVersion {
		fmt.Printf("ssl-cert-server v%s\n", VERSION)
		return
	}

	initConfig()
	manager := &Manager{
		m: &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       Cfg.Storage.Cache,
			RenewBefore: time.Duration(Cfg.LetsEncrypt.RenewBefore) * 24 * time.Hour,
			Client:      &acme.Client{DirectoryURL: Cfg.LetsEncrypt.DirectoryURL},
			Email:       Cfg.LetsEncrypt.Email,
			HostPolicy:  Cfg.LetsEncrypt.HostPolicy,
		},
		ForceRSA: Cfg.LetsEncrypt.ForceRSA,
	}
	go manager.listenCertChanges()

	mux := http.NewServeMux()
	buildRoutes(mux, manager)

	// Graceful restarts.
	upg, err := tableflip.New(tableflip.Options{
		UpgradeTimeout: time.Minute,
		PIDFile:        Cfg.PIDFile,
	})
	if err != nil {
		log.Fatalf("[FATAL] server: failed init upgrader: %v", err)
	}
	defer upg.Stop()

	// Do an upgrade on SIGHUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				log.Printf("[ERROR] server: filed do upgrade: err= %v", err)
			}
		}
	}()

	// Listen must be called before Ready
	ln, err := upg.Listen("tcp", Cfg.Listen)
	if err != nil {
		log.Fatalf("[FATAL] server: fialed listen: %v", err)
	}
	server := http.Server{Handler: mux}
	go func() {
		log.Printf("[INFO] server: listening on http://%v", Cfg.Listen)
		err := server.Serve(ln)
		if err != http.ErrServerClosed {
			log.Fatalf("[FATAL] server: stopped unexpectedly: %v", err)
		}
	}()

	if err := upg.Ready(); err != nil {
		log.Fatalf("[FATAL] server: upgrader not ready: %v", err)
	}

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-upg.Exit():
		log.Printf("[INFO] server: received exit signal from upgrader")
	case <-stop:
		log.Printf("[INFO] server: received stop signal from system")
	}

	// Graceful shutdown the old process.
	// Make sure to set a deadline on exiting the process after upg.Exit()
	// is closed. No new upgrades can be performed if the parent doesn't exit.
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Shutdown(ctx)
	if err == nil {
		log.Printf("[INFO] server: shutdown gracefully")
	} else {
		log.Printf("[WARN] server: failed graceful shutdown: %v", err)
	}
}

func PrintUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "To run certificate server:\n%s\n", os.Args[0])
	flag.CommandLine.PrintDefaults()

	fmt.Fprintf(flag.CommandLine.Output(), "\n")
	fmt.Fprintf(flag.CommandLine.Output(), "To generate self-signed certificate:\n%s %s\n",
		os.Args[0], generateSelfSignedCertSubCommand)
	generateSelfSignedCertFlagSet.PrintDefaults()
}
