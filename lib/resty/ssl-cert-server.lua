local cjson = require "cjson"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local resty_lock = require "resty.lock"
local resty_http = require "resty.http"

local _M = {}

function _M.new(options)
    options = options or {}

    local host, port
    if not options["backend"] then
        ngx.log(ngx.ERR, "ssl-cert-server: using default backend server 127.0.0.1:8999")
        options["backend"] = "127.0.0.1:8999"
    else
        host, port = options["backend"]:match("([^:]+):(%d+)")
        if not host then
            host = options["backend"]:match("^%d[%d%.]+%d$")
            if not host then
                ngx.log(ngx.ERR, "ssl-cert-server: invalid backend IP address, using default 127.0.0.1:8999")
                options["backend"] = "127.0.0.1:8999"
            else
                options["backend"] = host .. ":80"
            end
        end
    end
    host, port = options["backend"]:match("([^:]+):(%d+)")
    options["backend_host"] = host
    options["backend_port"] = tonumber(port or 80)

    if not options["allow_domain"] then
        options["allow_domain"] = function(domain)
            return false
        end
    end

    return setmetatable({ options = options }, { __index = _M })
end

local function request_cert(self, domain)
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        return nil, nil, nil, "cert: failed to connect backend server: " .. err
    end

    -- Get the certificate from backend cert server.
    local res, body, cert_json, suc, err
    httpc:set_timeout(60000)  -- 60 seconds
    res, err = httpc:request({ path = "/cert/" .. domain })
    if not err then
        if res.status ~= 200 then
            err = "bad HTTP status " .. res.status
        else
            body, err = res:read_body()
            if not err then
                suc, cert_json = pcall(cjson.decode, body)
                if not suc then
                    err = "invalid json data from backend server"
                end
            end
        end
    end
    if err then
        return nil, nil, nil, err
    end

    -- Convert certificate from PEM to DER format.
    local cert_der, pkey_der
    cert_der, err = ssl.cert_pem_to_der(cert_json["cert"])
    if not cert_der or err then
        return nil, nil, nil, "failed to convert certificate from PEM to DER: " .. err
    end
    pkey_der, err = ssl.priv_key_pem_to_der(cert_json["pkey"])
    if not pkey_der or _err then
        return nil, nil, nil, "failed to convert private key from PEM to DER: " .. err
    end

    return cert_der, pkey_der, cert_json["ttl"]
end

local function get_cert(self, domain)
    local cert, pkey, ttl, lock, elapsed, ok, err, lock_err, cache_err
    local cache = ngx.shared.ssl_certs_cache
    local bak_cert_key = "cert:" .. domain
    local bak_pkey_key = "pkey:" .. domain
    local cert_key = "cert:" .. domain .. ":latest"
    local pkey_key = "pkey:" .. domain .. ":latest"
    local lock_key = "lock:cert:" .. domain

    cert, cache_err = cache:get(cert_key)
    pkey, cache_err = cache:get(pkey_key)
    if (cert and pkey) then
        return cert, pkey
    end

    -- Lock to prevent multiple requests for same domain.
    lock, lock_err = resty_lock:new("ssl_certs_cache")
    if not lock then
        return nil, nil, "failed to create lock: " .. lock_err
    end
    elapsed, lock_err = lock:lock(lock_key)
    if not elapsed then
        return nil, nil, "failed to acquire lock: " .. lock_err
    end

    -- Check the cache again after holding the lock.
    cert, err = cache:get(cert_key)
    pkey, err = cache:get(pkey_key)
    if not (cert and pkey) then
        -- We are the first, request certificate from backend server.
        cert, pkey, ttl, err = request_cert(self, domain)
        if (cert and pkey) then
            -- Cache the newly requested certificate as long living backup.
            ok, cache_err, forcible = cache:set(bak_cert_key, cert)
            ok, cache_err, forcible = cache:set(bak_pkey_key, pkey)
            if forcible then
                ngx.log(ngx.WARNING, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching backup certificate)")
            end
        else
            -- Since certificate renewal happens far before expired on backend server,
            -- we can use the previous request result from cache if it exists.
            -- This avoids every request triggering certificate request to backend,
            -- which slow down nginx's performance and rise up nginx's pressure on busy site.
            --
            -- Also we consider an recently-expired certificate is more friendly to site user
            -- than fallback to self-signed certificate.
            cert, cache_err = cache:get(bak_cert_key)
            pkey, cache_err = cache:get(bak_pkey_key)

            -- TODO: we should handle the backend failure more carefully here,
            -- maybe inserting a stub value into the cache.
        end

        -- Cache the certificate and private key.
        if (cert and pkey) then
            ok, cache_err, forcible = cache:set(cert_key, cert, ttl)
            ok, cache_err, forcible = cache:set(pkey_key, pkey, ttl)
            if forcible then
                ngx.log(ngx.WARNING, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching new certificate)")
            end
        end
    end

    -- Release the lock.
    ok, lock_err = lock:unlock()
    if not ok then
        -- Don't return here, we may have gotten the cert and private key successfully.
        ngx.log(ngx.ERR, "failed to release lock: ", lock_err)
    end

    if not (cert and pkey) then
        return nil, nil, err
    end
    return cert, pkey
end

local function set_cert(self, cert_der, pkey_der)
    local ok, err

    -- Clear the default fallback certificates (defined in the hard-coded nginx configuration).
    ok, err = ssl.clear_certs()
    if not ok then
        return false, "failed to clear existing (fallback) certificates: " .. err
    end

    -- Set the public certificate chain.
    ok, err = ssl.set_der_cert(cert_der)
    if not ok then
        return false, "failed to set certificate: " .. err
    end

    -- Set the private key.
    ok, err = ssl.set_der_priv_key(pkey_der)
    if not ok then
        return false, "failed to set private key: " .. err
    end

    return true
end

local function request_stapling(self, domain)
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        return nil, nil, nil, "stapling: failed to connect backend server: " .. err
    end

    -- Get OCSP stapling from backend cert server.
    local stapling
    -- TODO: resolve ttl and expires from response headers. See: https://tools.ietf.org/html/rfc5019#section-6
    local ttl, expires = 3600, 3600
    httpc:set_timeout(10000)  -- 10 seconds
    local res, err = httpc:request({ path = "/ocsp/" .. domain })
    if not err then
        if res.status ~= 200 then
            err = "bad HTTP status code " .. res.status
        else
            stapling, err = res:read_body()
        end
    end
    if err then
        return nil, nil, nil, err
    end

    httpc:set_keepalive()
    return stapling, ttl, expires
end

local function get_stapling(self, domain)
    local stapling, ttl, expires, lock, elapsed, ok, err, lock_err, cache_err
    local cache = ngx.shared.ssl_certs_cache
    local bak_stapling_key = "stapling:" .. domain
    local stapling_key = "stapling:" .. domain .. ":latest"
    local lock_key = "lock:stapling:" .. domain

    stapling, cache_err = cache:get(stapling_key)
    if stapling then
        return stapling
    end

    -- Lock to prevent multiple requests for same domain.
    lock, lock_err = resty_lock:new("ssl_certs_cache")
    if not lock then
        return nil, "failed to create lock: " .. lock_err
    end
    elapsed, lock_err = lock:lock(lock_key)
    if not elapsed then
        return nil, "failed to acquire lock: " .. lock_err
    end

    stapling, cache_err = cache:get(stapling_key)
    if not stapling then
        stapling, ttl, expires, err = request_stapling(self, domain)
        if stapling then
            ok, cache_err, forcible = cache:set(bak_stapling_key, stapling, expires)
            if forcible then
                ngx.log(ngx.WARNING, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching backup OCSP stapling)")
            end
        else
            -- In case of backend failure, check backup for unexpired response.
            stapling, cache_err = cache:get(bak_stapling_key)
            expires, cache_err = cache:ttl(bak_stapling_key)
            -- TODO: calculate ttl from expires.
            ttl = 600

            -- TODO: we should handle the backend failure more carefully here,
            -- maybe inserting a stub value into the cache.
        end

        if (stapling and ttl) then
            ok, cache_err, forcible = cache:set(stapling_key, stapling, ttl)
            if forcible then
                ngx.log(ngx.WARNING, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching new OCSP stapling)")
            end
        end
    end

    -- Release the lock.
    ok, lock_err = lock:unlock()
    if not ok then
        ngx.log(ngx.ERR, "failed to release lock: ", lock_err)
    end

    if not stapling then
        return nil, err
    end
    return stapling
end

local function set_stapling(self, stapling)
    -- Set the OCSP stapling response.
    local ok, err = ocsp.set_ocsp_status_resp(stapling)
    if not ok then
        return false, "failed to set OCSP stapling"
    end
    return true
end

function _M.ssl_certificate(self)
    local domain, domain_err = ssl.server_name()
    if not domain or domain_err then
        ngx.log(ngx.WARN, "could not determine domain for request (SNI not supported?): ", domain_err)
        return
    end

    -- Check the domain is one we allow for handling SSL.
    local allow_domain = self.options["allow_domain"]
    if not allow_domain(domain) then
        ngx.log(ngx.NOTICE, domain, ": domain not allowed")
        return
    end

    local cert, pkey, err = get_cert(self, domain)
    if (cert and pkey) then
        ok, err = set_cert(self, cert, pkey)
        if not ok then
            ngx.log(ngx.ERR, domain, ": ", err)
            return
        end
    else
        ngx.log(ngx.ERR, domain, ": ", err)
        return
    end

    local stapling, err = get_stapling(self, domain)
    if stapling then
        ok, err = set_stapling(self, stapling)
        if not ok then
            ngx.log(ngx.ERR, domain, ": ", err)
            return
        end
    else
        ngx.log(ngx.ERR, domain, ": ", err)
        return
    end
end

function _M.challenge_server(self)
    local domain, err = ssl.server_name()
    local allow_domain = self.options["allow_domain"]
    if not allow_domain(domain) then
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end

    -- Pass challenge request to backend cert server.
    local httpc = http.new()
    httpc:set_timeout(500)
    local ok, err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        ngx.log(ngx.ERR, "challenge: failed to connect backend server: ", err)
        ngx.exit(ngx.BAD_GATEWAY)
    end

    httpc:set_timeout(2000)
    httpc:proxy_response(httpc:proxy_request())
    httpc:set_keepalive()
end

return _M
