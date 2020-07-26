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
	certServer := flag.String("cert-server", "127.0.0.1:8999", "ssl-cert-server host:port")
	flag.Parse()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("It works!"))
	}

	tlsConfig := tlsconfig.NewConfig(*certServer, nil)
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	http.Serve(listener, http.HandlerFunc(handler))
}
