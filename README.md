# ssl-cert-server

On the fly free SSL registration and renewal inside [OpenResty/nginx](http://openresty.org) with [Let's Encrypt](https://letsencrypt.org).

This OpenResty plugin automatically and transparently issues SSL certificates from Let's Encrypt as requests are received.

This uses the `ssl_certificate_by_lua` functionality in OpenResty 1.9.7.2+.

By using ssl-cert-server to register SSL certificates with Let's Encrypt, you agree to the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/).

I got inspires and stole some code from the awesome project [lua-resty-auto-ssl](https://github.com/GUI/lua-resty-auto-ssl) and Golang's autocert package, many thanks 😀

## Status

Considered STABLE.
This program has been running for more than 2 years for my personal sites, but as is a spare-time project,
anyone interested with this is HIGHLY RECOMMENDED to do testing in your environment.

NOTE:

The release version 0.1.x has a bug which may cause dead loop in OCSP stapling updater after months long running.
The bug has not much impact on CPU usage, but will blow up the logging files.

If anyone is using the 0.1.x release, please consider upgrade to newer release as soon as possible.

## Installation

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

Then download the cert server service binary file, either build by yourself:

`go get github.com/jxskiss/ssl-cert-server`

Or, download prebuilt binaries from the [release page](https://github.com/jxskiss/ssl-cert-server/releases).

Run your cert server (eg: for any sub-domain of example.com):

```bash
/path/to/ssl-cert-server --listen=127.0.0.1:8999 \
    --email=admin@example.com \
    --pattern=".*\\.example\\.com$"
```

For all available options for `ssl-cert-server` service, please see the "Available options" section.

Now you can configure your OpenResty to use the cert server for SSL certificates, see the following configuration example.

## Configuration Example

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
        cert_server = (require "resty.ssl-cert-server").new({
            backend = '127.0.0.1:8999',
            allow_domain = allow_domain
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
        # openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        #   -subj '/CN=sni-support-required-for-valid-ssl' \
        #   -keyout /etc/nginx/certs/fallback-self-signed.key \
        #   -out /etc/nginx/certs/fallback-self-signed.crt
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

## Available options for cert server

```text
Usage of ssl-cert-server:
  -listen string
        listen address, be sure DON't open to the world (default "127.0.0.1:8999")
  -email string
        contact email, if Let's Encrypt client's key is already registered, this is not used
  -force-rsa
        generate certificates with 2048-bit RSA keys (default false)
  -before int
        renew certificates before how many days (default 30)
  -cache-dir string
        which directory to cache certificates (default "./secret-dir")
  -domain value
        allowed domain names (may be given multiple times)
  -pattern value
        allowed domain regex pattern using POSIX ERE (egrep) syntax, (may be given multiple times,
        will be ignored when domain parameters supplied)
  -staging
        use Let's Encrypt staging directory (default false)
  -version
        print version string and quit
```

## Dependency

- [OpenResty](https://openresty.org/)
- [lua-resty-http](https://github.com/pintsized/lua-resty-http)

## Changes

### v0.3.0 @ 2020-03-13

- new: optional redis as cache storage
- change: update autocert to support ACMEv2
- change: use go module to manage golang dependency

### v0.2.1 @ 2018-10-10

- change: tidy logging messages
- change: minor improvements

### v0.2.0 @ 2018-08-11

- fix: dead loop in OCSP stapling updater after months long running
- change: remove unnecessary golang dependencies (`gocraft/web`, `jxskiss/glog`), resulting smaller binary size and easier installation
- change: since glog dependency has been removed, the flags provided by glog are not available anymore
- change: use official `acme/autocert` package instead of forking, makes code clearer and allows easier tracking of upstream changes
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
