package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/tableflip"

	"github.com/jxskiss/ssl-cert-server/server"
)

const VERSION = "0.4.2"

// StringArray implements flag.Value interface.
type StringArray []string

func (v *StringArray) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func (v *StringArray) String() string {
	return strings.Join(*v, ",")
}

func main() {
	defer server.FlushLogs()
	flag.Usage = PrintUsage
	if len(os.Args) >= 2 && os.Args[1] == generateSelfSignedCertSubCommand {
		cmdGenerateSelfSignedCertificate()
		return
	}
	server.InitFlags()
	if server.Flags.ShowVersion {
		fmt.Printf("ssl-cert-server v%s\n", VERSION)
		return
	}
	Cfg := server.Cfg

	server.InitConfig()
	mux := http.NewServeMux()
	manager := server.GetManager()
	manager.BuildRoutes(mux)

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
	httpServer := http.Server{Handler: mux}
	go func() {
		log.Printf("[INFO] server: listening on http://%v", Cfg.Listen)
		err := httpServer.Serve(ln)
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
	err = httpServer.Shutdown(ctx)
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

/*
Sub command to generate self-signed certificate.
*/

const generateSelfSignedCertSubCommand = "generate-self-signed"

var generateSelfSignedCertFlagSet = flag.NewFlagSet(generateSelfSignedCertSubCommand, flag.ExitOnError)
var generateSelfSignedCertOptions = struct {
	validDays    int
	out          string
	certOut      string
	keyOut       string
	organization StringArray
}{}

func init() {
	cmdFlags := generateSelfSignedCertFlagSet
	cmdFlags.IntVar(&generateSelfSignedCertOptions.validDays,
		"valid-days", 365, "number of days the cert is valid for")
	cmdFlags.StringVar(&generateSelfSignedCertOptions.out,
		"out", "./self_signed", "output single file contains both private key and certificate")
	cmdFlags.StringVar(&generateSelfSignedCertOptions.certOut,
		"cert-out", "./self_signed.cert", "output certificate file")
	cmdFlags.StringVar(&generateSelfSignedCertOptions.keyOut,
		"key-out", "./self_signed.key", "output private key file")
	cmdFlags.Var(&generateSelfSignedCertOptions.organization,
		"organization", "certificate organization (may be given multiple times)")
}

func cmdGenerateSelfSignedCertificate() {
	generateSelfSignedCertFlagSet.Parse(os.Args[2:])
	opts := generateSelfSignedCertOptions
	if len(opts.organization) == 0 {
		opts.organization = server.DefaultSelfSignedOrganization
	}

	certPEM, privKeyPEM, err := server.CreateSelfSignedCertificate(opts.validDays, opts.organization)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	err = ioutil.WriteFile(opts.keyOut, privKeyPEM, 0644)
	if err == nil {
		err = ioutil.WriteFile(opts.certOut, certPEM, 0644)
	}
	if err == nil {
		outData := append(privKeyPEM, certPEM...)
		err = ioutil.WriteFile(opts.out, outData, 0644)
	}
	if err != nil {
		log.Fatalf("[FATAL] self_signed: failed write certificate files: %v", err)
	}
}
