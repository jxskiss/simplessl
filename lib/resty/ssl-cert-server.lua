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

local function safe_connect(self)
    -- TODO: do we really need this complication?

    local lock_key = "lock:backend:connect"
    local failure_key = "backend:failure"
    local cache = ngx.shared.ssl_certs_cache

    -- failure: "sleep_seconds:previous_time"
    local failure, cache_err = cache:get(failure_key)
    if cache_err then
        return nil, "failed to get backend failure status from cache"
    end
    local sleep, previous
    if failure then
        sleep, previous = failure:match("([^:]+):(.+)")
        if ngx.now() - tonumber(previous) < tonumber(sleep) then
            return nil, "backend is in unhealthy state"
        end
    end

    local lock, lock_err = resty_lock:new("ssl_certs_cache", {exptime = 1, timeout = 1})
    if not lock then
        return nil, "failed to create lock: " .. (lock_err or "nil")
    end
    local elapsed, lock_err = lock:lock(lock_key)
    if not elapsed then
        return nil, "failed to acquire lock: " .. (lock_err or "nil")
    end

    -- Check again.
    failure, cache_err = cache:get(failure_key)
    if cache_err then
        return nil, "failed to get backend failure status from cache"
    end
    if failure then
        sleep, previous = failure:match("([^:]+):(.+)")
        if ngx.now() - tonumber(previous) < tonumber(sleep) then
            local ok, lock_err = lock:unlock()
            if not ok then
                ngx.log(ngx.ERR, "failed to release lock: ", lock_err)
            end
            return nil, "backend is in unhealthy state"
        end
    end

    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, conn_err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        -- Block further connections to avoid slowing down nginx too much for busy website
        sleep = sleep or 2
        if failure then
            -- Connect to backend as soon as possible, no more than 5 minutes.
            sleep = sleep * 2
            if sleep > 300 then
                sleep = 300
            end
        end
        ngx.log(ngx.ERR, "backend is in unhealthy state, block for ", sleep, " seconds")
        ok, err = cache:set(failure_key, sleep .. ":" .. ngx.now())
        local ok, lock_err = lock:unlock()
        if not ok then
            ngx.log(ngx.ERR, "failed to release lock: ", lock_err)
        end
        return nil, conn_err
    end

    -- Connect backend success, delete the failure status.
    local ok, cache_err = cache:delete(failure_key)
    if not ok then
        ngx.log(ngx.ERR, "failed to delete backend failure key: ", cache_err)
    end

    local ok, lock_err = lock:unlock()
    if not ok then
        ngx.log(ngx.ERR, "failed to release lock: ", lock_err)
    end
    return httpc
end

local function request_cert(self, domain, timeout)
    local httpc, err = safe_connect(self)
    if err ~= nil then
        return nil, nil, nil, err
    end

    -- Get the certificate from backend cert server.
    local res, body, cert_json, suc, err
    httpc:set_timeout(timeout * 1000)
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
        return nil, nil, nil, "failed to convert certificate from PEM to DER: " .. (err or "nil")
    end
    pkey_der, err = ssl.priv_key_pem_to_der(cert_json["pkey"])
    if not pkey_der or _err then
        return nil, nil, nil, "failed to convert private key from PEM to DER: " .. (err or "nil")
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
    local lock_exptime = 120

    cert, cache_err = cache:get(cert_key)
    pkey, cache_err = cache:get(pkey_key)
    if (cert and pkey) then
        return cert, pkey
    end

    -- Lock to prevent multiple requests for same domain.
    lock, lock_err = resty_lock:new("ssl_certs_cache", {exptime = lock_exptime, timeout = lock_exptime})
    if not lock then
        return nil, nil, "failed to create lock: " .. (lock_err or "nil")
    end
    elapsed, lock_err = lock:lock(lock_key)
    if not elapsed then
        return nil, nil, "failed to acquire lock: " .. (lock_err or "nil")
    end

    -- Check the cache again after holding the lock.
    cert, cache_err = cache:get(cert_key)
    pkey, cache_err = cache:get(pkey_key)
    if not (cert and pkey) then
        -- We are the first, request certificate from backend server.
        cert, pkey, ttl, err = request_cert(self, domain, lock_exptime - 10)
        if (cert and pkey) then
            -- Cache the newly requested certificate as long living backup.
            ok, cache_err, forcible = cache:set(bak_cert_key, cert)
            ok, cache_err, forcible = cache:set(bak_pkey_key, pkey)
            if forcible then
                ngx.log(ngx.WARN, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching backup certificate)")
            end
        else
            -- Since certificate renewal happens far before expired on backend server,
            -- most probably the previous backup certificate is valid, we use it if it exists.
            -- This avoids further requests within next cache period triggering certificate
            -- requests to backend, which slow down nginx's performance and rise up nginx's
            -- pressure on busy site.
            -- Also we consider an recently-expired certificate is more friendly to site user
            -- than fallback to self-signed certificate.
            cert, cache_err = cache:get(bak_cert_key)
            pkey, cache_err = cache:get(bak_pkey_key)
            ttl = 300
        end

        -- Cache the certificate and private key.
        if (cert and pkey) then
            ok, cache_err, forcible = cache:set(cert_key, cert, ttl)
            ok, cache_err, forcible = cache:set(pkey_key, pkey, ttl)
            if forcible then
                ngx.log(ngx.WARN, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching new certificate)")
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
        return false, "failed to clear existing (fallback) certificates: " .. (err or "nil")
    end

    -- Set the public certificate chain.
    ok, err = ssl.set_der_cert(cert_der)
    if not ok then
        return false, "failed to set certificate: " .. (err or "nil")
    end

    -- Set the private key.
    ok, err = ssl.set_der_priv_key(pkey_der)
    if not ok then
        return false, "failed to set private key: " .. (err or "nil")
    end

    return true
end

local function request_stapling(self, domain, timeout)
    local httpc, err = safe_connect(self)
    if err ~= nil then
        return nil, err
    end

    -- Get OCSP stapling from backend cert server.
    local stapling
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
        return nil, nil, err
    end

    -- Parse TTL from response header "Cache-Control".
    local ttl = 60
    if res.headers["Cache-Control"] then
        local m, err = ngx.re.match(res.headers["Cache-Control"], [[max-age=(\d+)]])
        if m then
            ttl = tonumber(m[1])
        end
    end

    httpc:set_keepalive()
    return stapling, ttl
end

local function get_stapling(self, domain)
    local stapling, ttl, expires, lock, elapsed, ok, err, lock_err, cache_err
    local cache = ngx.shared.ssl_certs_cache
    local bak_stapling_key = "stapling:" .. domain
    local stapling_key = "stapling:" .. domain .. ":latest"
    local lock_key = "lock:stapling:" .. domain
    local lock_exptime = 10

    stapling, cache_err = cache:get(stapling_key)
    if stapling then
        return stapling
    end

    -- Lock to prevent multiple requests for same domain.
    lock, lock_err = resty_lock:new("ssl_certs_cache", {exptime = lock_exptime, timeout=lock_exptime})
    if not lock then
        return nil, "failed to create lock: " .. (lock_err or "nil")
    end
    elapsed, lock_err = lock:lock(lock_key)
    if not elapsed then
        return nil, "failed to acquire lock: " .. (lock_err or "nil")
    end

    stapling, cache_err = cache:get(stapling_key)
    if not stapling then
        -- We are the first, request OCSP stapling from backend server.
        stapling, ttl, err = request_stapling(self, domain, lock_exptime - 2)
        if stapling then
            ok, cache_err, forcible = cache:set(bak_stapling_key, stapling, ttl)
            if forcible then
                ngx.log(ngx.WARN, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching backup OCSP stapling)")
            end
        else
            -- In case of backend failure, check backup for unexpired response.
            stapling, cache_err = cache:get(bak_stapling_key)
            ttl, cache_err = cache:ttl(bak_stapling_key)
        end

        if (stapling and ttl) then
            ok, cache_err, forcible = cache:set(stapling_key, stapling, ttl)
            if forcible then
                ngx.log(ngx.WARN, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while caching new OCSP stapling)")
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
