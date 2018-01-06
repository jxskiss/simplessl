# ssl-cert-server

On the fly free SSL registration and renewal inside [OpenResty/nginx](http://openresty.org) with [Let's Encrypt](https://letsencrypt.org).

This OpenResty plugin automatically and transparently issues SSL certificates from Let's Encrypt as requests are received.

This uses the `ssl_certificate_by_lua` functionality in OpenResty 1.9.7.2+.

By using ssl-cert-server to register SSL certificates with Let's Encrypt, you agree to the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/).

I got inspires and stole some code from the awesome project [lua-resty-auto-ssl](https://github.com/GUI/lua-resty-auto-ssl) and Golang's autocert package, many thanks 😀

## Status

Considered BETA, used in our deployment.

Users are highly RECOMMENDED to do testing in your environment.

## Install

Download tarball from the [release page](https://github.com/jxskiss/ssl-cert-server/releases), then:

1. put file `resty/ssl-cert-server.lua` under your OpenResty's lua path;
2. put file `bin/ssl-cert-server[.exe]` to somewhere and remember the path;
3. run the cert server, see the following example;
4. configure your OpenResty to use the cert server for SSL certificates, see the following configuration example.

Cert server example (for any sub-domain of example.com):

`/path/to/ssl-cert-server --listen=127.0.0.1:8999 --logtostderr --email=admin@example.com --pattern=".*\\.example\\.com$"`

All available options for `ssl-cert-server`:

```text
Usage of ssl-cert-server:
  -alsologtostderr
        log to standard error as well as files
  -before int
        renew certificates before how many days (default 30)
  -cache-dir string
        which directory to cache certificates (default "./secret-dir")
  -domain value
        allowed domain names (may be given multiple times)
  -email string
        contact email, if Let's Encrypt client's key is already registered, this is not used
  -force-rsa
        generate certificates with 2048-bit RSA keys (default false)
  -listen string
        listen address, be sure DON't open to the world (default "127.0.0.1:8999")
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace
  -log_dir string
        If non-empty, write log files in this directory
  -logtostderr
        log to standard error instead of files
  -pattern value
        allowed domain regex pattern using POSIX ERE (egrep) syntax, (may be given multiple times,
        will be ignored when domain parameters supplied)
  -shortlog
        use simple short log header (default true)
  -staging
        use Let's Encrypt staging directory (default false)
  -stderrthreshold value
        logs at or above this threshold go to stderr
  -v value
        log level for V logs
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```

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
        -- Define a funcction to determine which SNI domains to automatically
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
        server_name example.com;

        # Endpoint used for performing domain verification with Let's Encrypt.
        location /.well-known/acme-challenge/ {
            content_by_lua_block {
                cert_server:challenge_server()
            }
        }
    }

}
```

## TODO

1. ~~Implement better cache strategy;~~
2. ~~Handle backend server failure more robustly;~~
3. ~~Test case for both cert-server and openresty library~~
   (The acme-related work is done by golang's acme/autocert package,
   which is well tested. Any error in the lua library and golang
   request handlers are carefully handled.)
