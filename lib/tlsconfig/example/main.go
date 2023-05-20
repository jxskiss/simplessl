package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/jxskiss/simplessl/lib/tlsconfig"
)

func main() {
	port := flag.Int("port", 6601, "port to listen")
	certServer := flag.String("cert-server", "127.0.0.1:8999", "simplessl host:port")
	flag.Parse()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("It works!"))
	}

	tlsConfig := tlsconfig.NewConfig(*certServer, tlsconfig.Options{})
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	http.Serve(listener, http.HandlerFunc(handler))
}
