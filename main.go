package main

import (
	"context"
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
	initFlags()
	prepareConfig()

	if config.ShowVersion {
		fmt.Printf("ssl-cert-server v%s\n", VERSION)
		return
	}
	err := store.parse()
	if err != nil {
		log.Fatalf("[FATAL] server: failed parse cache storeage: %v", err)
	}

	manager := &Manager{
		m: &autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       store,
			RenewBefore: time.Duration(config.Before) * 24 * time.Hour,
			Client:      &acme.Client{DirectoryURL: config.DirectoryURL},
			Email:       config.Email,
			HostPolicy:  config.HostPolicy,
		},
		ForceRSA: config.ForceRSA,
	}
	go manager.listenCertChanges()

	mux := http.NewServeMux()
	buildRoutes(mux, manager)

	// Graceful restarts.
	upg, err := tableflip.New(tableflip.Options{
		UpgradeTimeout: time.Minute,
		PIDFile:        config.PIDFile,
	})
	if err != nil {
		log.Fatalf("[FATAL] server: failed init upgrader: %v", err)
	}
	defer upg.Stop()

	// Do an upgrade on SIGUP
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			err := upg.Upgrade()
			if err != nil {
				log.Printf("[ERROR] server: filed do upgrade: %v", err)
			}
		}
	}()

	// Listen must be called before Ready
	ln, err := upg.Listen("tcp", config.Listen)
	if err != nil {
		log.Fatalf("[FATAL] server: fialed listen: %v", err)
	}
	server := http.Server{Handler: mux}
	go func() {
		log.Printf("[INFO] server: listening on http://%v", config.Listen)
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
