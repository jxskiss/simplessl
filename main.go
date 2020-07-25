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

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	initFlags()
	prepareConfig()

	if config.ShowVersion {
		fmt.Printf("ssl-cert-server v%s\n", VERSION)
		return
	}
	err := store.parse()
	if err != nil {
		log.Fatalf("failed parse cache storeage: %v", err)
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
	server := http.Server{Addr: config.Listen, Handler: mux}
	go func() {
		log.Printf("[INFO] server: listening on http://%v", config.Listen)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalln("[FATAL] server: stopped unexpectly: err=", err)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(ctx)
	log.Println("[INFO] server: shutdown gracefully")
}
