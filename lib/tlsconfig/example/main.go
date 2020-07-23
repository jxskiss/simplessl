package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/jxskiss/ssl-cert-server/lib/tlsconfig"
)

func main() {
	port := flag.Int("port", 6601, "port to listen")
	sslServer := flag.String("ssl-server", "127.0.0.1:8999", "ssl-cert-server host")
	flag.Parse()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	tlsConfig := tlsconfig.NewConfig(*sslServer)
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	http.Serve(listener, http.HandlerFunc(handler))
}
