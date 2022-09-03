# ssl-cert-server

On the fly free SSL registration and renewal inside [OpenResty/nginx](http://openresty.org)
and any Golang TLS program, with [Let's Encrypt](https://letsencrypt.org).

The ssl-cert-server automatically and transparently issues SSL certificates from Let's Encrypt
as requests are received, when a certificate needs a renewal, it automatically renews the
certificate asynchronously in background.

The Openresty plugin uses the `ssl_certificate_by_lua` functionality in OpenResty 1.9.7.2+.

By using ssl-cert-server to register SSL certificates with Let's Encrypt,
you agree to the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/).

Disclaimer: I got initial inspires and stole some code from the awesome
project [lua-resty-auto-ssl](https://github.com/GUI/lua-resty-auto-ssl) and Go's autocert package.
Also, this program uses [Lego](https://github.com/go-acme/lego) to solve dns-01 challenge.
Many thanks 😀

## Features

1. Minimal dependency, easy deployment, friendly to distributed environment.
2. High performance, very low latency added to user requests.
3. Issue and renew certificate for each domain using http-01 challenge, support Openresty and Golang.
4. Issue and renew certificate for each domain using tls-alpn-01 challenge, support Golang.
5. Issue and renew **wildcard certificate**, using dns-01 challenge, support Openresty and Golang.
6. Serve manually-managed certificates.
7. Serve OCSP stapling, with cache and asynchronous renewal, the latency is negligible.
8. Generate and serve self-signed certificate.
9. Graceful restart like Nginx without losing any requests.
10. Support directory and Redis as cache storage, adding new storage support is easy.

**NOTE: currently this program is designed to be used inside intranet,
security features are not seriously considered, be sure to PROTECT your certificate server
properly and keep an eye on security concerns.**

## Centric certificate server

Compared to other similar projects, this project provides a centric certificate server
to manage all your certificates (both auto issued or manually managed, and self-signed) in one place.
The OpenResty plugin and Golang TLS config library acts as client to the server.

By this design, there are several advantages:

1. Offload ACME related work and communication with storage to the backend Golang server,
   let Nginx/OpenResty do what it is designed for and best at;
1. It's more friendly to distributed deployments, one can manage all certificates in a single place,
   the OpenResty plugin and Golang library deployment is simple and straightforward;
   you get single certificate for a domain, not as many certificates as your
   web server instances (as some other similar project does);
1. Golang program is considered easier to maintain and do troubleshooting than
   doing ACME work and storage with Lua;
1. Also, Golang program is considered easier to extend to support new type of storage,
   or new features (e.g. wildcard certificates, security, etc.);

A multi-layered cache mechanism is used to help frontend Nginx and Golang web servers
automatically update to renewed certificates with negligible performance penalty, and
without any reloading:

- OpenResty per-worker LRU cache with cdata pointer (Golang client uses in memory copy-on-write cache), fallback to
- OpenResty shared memory cache (not needed for Golang client), fallback to
- In-memory cache within backend ssl-cert-server, finally go to
- Storage or ACME server.

The cached certificates and OCSP staple is automatically renewed and refreshed in backend ssl-cert-server.

## Status

Considered BETA.

Although this program has been running for nearly 5 years supporting my personal sites,
however this is a spare-time project and has not known deployment for large production systems.

**Anyone interested with this is HIGHLY RECOMMENDED to do testing in your environment.**

## Installation

### For Openresty

The lua library is published with [OPM](https://opm.openresty.org/),
the following command will install the ssl-cert-server library, as well as it's dependency "lua-resty-http".

`opm get jxskiss/ssl-cert-server`

If you do not have opm, you can install the lua libraries manually, take OpenResty
installed under "/usr/local/openresty" as example (you may need to use sudo to grant proper permission):

```bash
mkdir -p /usr/local/openresty/site/lualib/resty
cd /usr/local/openresty/site/lualib/resty
wget https://raw.githubusercontent.com/pintsized/lua-resty-http/master/lib/resty/http.lua
wget https://raw.githubusercontent.com/pintsized/lua-resty-http/master/lib/resty/http_headers.lua
wget https://raw.githubusercontent.com/jxskiss/ssl-cert-server/master/lib/resty/ssl-cert-server.lua
```

### For Golang TLS program

`go get github.com/jxskiss/ssl-cert-server/lib/tlsconfig@latest`

See the following doc for example of using `lib/tlsconfig`.

### Run ssl-cert-server

Download the cert server service binary file, either build by yourself:

`go install github.com/jxskiss/ssl-cert-server@latest`

or download prebuilt binaries from the [release page](https://github.com/jxskiss/ssl-cert-server/releases).

Copy `example.conf.yaml` to your favorite location and edit it to fit your need.
Configuration options are explained in the example file.

Run your cert server:

```bash
/path/to/ssl-cert-server run -c /path/to/your/conf.yaml
```

Or to generate a self-signed certificate, see `ssl-cert-server generate-self-signed -h`.

Now you can configure your OpenResty or Golang program to use the cert server for SSL certificates,
see the following examples.

## Nginx configuration example

```conf
events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    lua_shared_dict ssl_certs_cache 1m;

    init_by_lua_block {
        -- Define a function to determine which SNI domains to automatically
        -- handle and register new certificates for. Defaults to not allowing
        -- any domain, so this must be configured.
        function allow_domain(domain)
            if domain:find("example.com$") then
                return true
            end
            return false
        end

        -- Initialize backend certificate server instance.
        -- Change lru_maxitems according to your deployment, default 100.
        cert_server = (require "resty.ssl-cert-server").new({
            backend = '127.0.0.1:8999',
            allow_domain = allow_domain,
            lru_maxitems = 100,
        })
    }

    # HTTPS Server
    server {
        listen 443 ssl;

        # Works also with non-default HTTPS port.
        listen 8443 ssl;

        server_name hello.example.com;

        # Dynamic handler for issuing or returning certs for SNI domains.
        ssl_certificate_by_lua_block {
            cert_server:ssl_certificate()
        }

        # Fallback certificate required by nginx, self-signed is ok.
        # ssl-cert-server generate-self-signed \
        #   -days 3650 \
        #   -cert-out /etc/nginx/certs/fallback-self-signed.crt \
        #   -key-out /etc/nginx/certs/fallback-self-signed.key
        ssl_certificate /etc/nginx/certs/fallback-self-signed.crt;
        ssl_certificate_key /etc/nginx/certs/fallback-self-signed.key;

        location / {
            content_by_lua_block {
                ngx.say("It works!")
            }
        }
    }

    # HTTP Server
    server {
        listen 80;
        server_name hello.example.com;

        # Endpoint used for performing domain verification with Let's Encrypt.
        location /.well-known/acme-challenge/ {
            content_by_lua_block {
                cert_server:challenge_server()
            }
        }
    }

}
```

## Golang `lib/tlsconfig`

You may use the package `lib/tlsconfig` to run Golang program with TLS. eg:

```go
func main() {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("It works!"))
	}

	// See doc of tlsconfig.Options for available options.
	tlsConfig := tlsconfig.NewConfig("127.0.0.1:8999", tlsconfig.Options{})
	listener, err := tls.Listen("tcp", ":8443", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	http.Serve(listener, http.HandlerFunc(handler))
}
```

## Dependency

- [OpenResty](https://openresty.org/) >= 1.9.7.2
- [lua-resty-http](https://github.com/ledgetech/lua-resty-http) >= 0.16.1

## Change history

### v0.5.0 @ 2022-06-12

- fix: incorrect behavior when querying OCSP stapling before query certificate
- new: support wildcard certificates, using Lego to solve dns-01 challenge
- change: make `lib/tlsconfig` be standalone module
- change: upgrade dependency to latest
- change: refactor code to use more sophisticated cli and logging libraries
- change: refactor code for better maintainability

### v0.4.3 @ 2022-05-17

- fix: OCSP stapling which failed because the wrong certificate was selected as issuer certificate,
  thanks @cedricdubois (#6)
- new: optional "prefix" option for Redis storage

### v0.4.2 @ 2021-06-02

- fix: request failed when only configured default cert available, #2
- fix: suppress log messages when the OCSP server returns error, #3
- change: upgrade dependency to latest

### v0.4.1 @ 2020-08-23

- new: support tls-alpn-01 challenge for Golang library
- new: use cdata pointer instead of der for LRU cache
- change: remove OCSP stapling from LRU cache which is unnecessary and not been properly refreshed

### v0.4.0 @ 2020-08-16

Update: this release has known bugs, please upgrade to newer release.

- new: support managed certificates
- new: support self-signed certificate
- new: Golang library to use with arbitrary Golang program which needs TLS support
- new: sub-command to generate a self-signed certificate
- new: (lua) layered cache for sake of best performance (per-worker LRU cache + shared memory cache)
- new: graceful restart like Nginx without losing any request
- change: use YAML configuration file to replace command line flags,
  since we support more features, the command line flags is not enough to do configuration
- change: (internal) reorganize code into smaller files for better maintainability
- change: (internal) optimize lua shared memory cache using for better performance
- fix: add fingerprint to certificate and OCSP staple cache, to make sure
  we get correct OCSP staple for the corresponding certificate, without this,
  incorrect OCSP staple cache may be used for a short period after the certificate is renewed

This release is a major change with quite a lot of new features and improvements.

### v0.3.0 @ 2020-03-13

- new: optional redis as cache storage
- change: update autocert to support ACMEv2
- change: use go module to manage golang dependency

### v0.2.1 @ 2018-10-10

- change: tidy logging messages
- change: minor improvements

### v0.2.0 @ 2018-08-11

- fix: dead loop in OCSP stapling updater after months long running
- change: remove unnecessary golang dependencies (`gocraft/web`, `jxskiss/glog`),
  resulting smaller binary size and easier installation
- change: since glog dependency has been removed, the flags provided by glog are not available anymore
- change: use official `acme/autocert` package instead of forking,
  makes code clearer and allows easier tracking of upstream changes
- new: use glide to manage golang dependencies

### v0.1.2 @ 2018-06-20

- fix: 408 Request Time-out from OCSP stapling server

### v0.1.1 @ 2018-01-06

Initial public release.

## TODO

1. ~~Implement better cache strategy;~~
2. ~~Handle backend server failure more robustly;~~
3. ~~Test case for both cert-server and openresty library~~
   (The acme-related work is done by golang's acme/autocert package,
   which is well tested. Any error in the lua library and golang
   request handlers are carefully handled.)
