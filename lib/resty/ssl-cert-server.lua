local cjson = require "cjson"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local resty_lock = require "resty.lock"
local resty_http = require "resty.http"

local _M = { _VERSION = '0.3.0' }

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

local function _log_unlock(lock)
    local ok, lock_err = lock:unlock()
    if not ok then
        ngx.log(ngx.ERR, "failed to unlock: " .. lock_err)
        return false
    end
    return true
end

local function _lock(key, opts)
    local lock, lock_err = resty_lock:new("ssl_certs_cache", opts)
    if not lock then
        return nil, "failed to create lock: " .. lock_err
    end
    local elapsed, lock_err = lock:lock(key)
    if not elapsed then
        return nil, "failed to acquire lock: " .. lock_err
    end
    return lock
end

local function _safe_set_cache(values)
    local lock, lock_err = _lock("lock:_safe_set_cache", {exptime = 1, timeout = 1})
    if not lock then
        return false, lock_err
    end

    local cache = ngx.shared.ssl_certs_cache
    for k, v_ttl in pairs(values) do
        local ok, cache_err, forcible = cache:set(k, v_ttl[1], v_ttl[2] or 0)
        if forcible then
            ngx.log(ngx.WARN, "'lua_shared_dict ssl_certs_cache' might be too small - consider increasing its size")
        end
        if not ok then
            _log_unlock(lock)
            return false, "failed to set cache: " .. cache_err
        end
    end

    _log_unlock(lock)
    return true
end

local function safe_connect(self)
    local lock_key = "lock:backend:connect"
    local failure_key = "backend:failure"
    local cache = ngx.shared.ssl_certs_cache

    local failure, cache_err = cache:get(failure_key)
    if cache_err then
        return nil, "failed to get backend failure status: " .. cache_err
    end
    local sleep, previous
    if failure then
        local data = cjson.decode(failure)
        sleep, previous = data['sleep'], data['previous']
        if ngx.now() - previous < sleep then
            return nil, "backend is in unhealthy state"
        end
    end

    local lock, lock_err = _lock(lock_key, {exptime = 1, timeout = 1})
    if not lock then
        return nil, lock_err
    end

    -- Check again after holding lock.
    failure, cache_err = cache:get(failure_key)
    if cache_err then
        _log_unlock(lock)
        return nil, "failed to get backend failure status: " .. cache_err
    end
    if failure then
        local data = cjson.decode(failure)
        sleep, previous = data['sleep'], data['previous']
        if ngx.now() - previous < sleep then
            _log_unlock(lock, lock_key)
            return nil, "backend is in unhealthy state"
        end
    end

    -- Backend looks all right, try it.
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, conn_err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        -- Block further connections to avoid slowing down nginx too much for busy website.
        -- Connect to backend as soon as possible, no more than 5 minutes.
        if not sleep then
            sleep = 2
        else
            sleep = sleep * 2
            if sleep > 300 then
                sleep = 300
            end
        end
        ngx.log(ngx.ERR, "backend in unhealthy state, block for ", sleep, " seconds")
        local ok, cache_err = cache:set(failure_key, cjson.encode({ sleep = sleep, previous = ngx.now() }))
        if not ok then
            ngx.log(ngx.ERR, "failed to set backend failure status: ", cache_err)
        end
        _log_unlock(lock)
        return nil, conn_err
    end

    -- Connect backend success, clear failure status if exists.
    if failure then
        local ok, cache_err = cache:delete(failure_key)
        if not ok then
            ngx.log(ngx.ERR, "failed to delete backend failure status: ", cache_err)
        end
    end
    _log_unlock(lock)
    return httpc
end

local function make_request(self, opts, timeout, decode_json)
    local httpc, conn_err = safe_connect(self)
    if conn_err ~= nil then
        return nil, nil, conn_err
    end
    httpc:set_timeout((timeout or 5) * 1000)
    local res, req_err = httpc:request(opts)
    local body, headers
    if res then
        if res.status ~= 200 then
            req_err = "bad HTTP status " .. res.status
        else
            headers = res.headers
            body, req_err = res:read_body()
            if body and decode_json then
                local suc
                suc, body = pcall(cjson.decode, body)
                if not suc then
                    req_err = "invalid json data from server"
                end
            end
        end
    end
    if req_err then
        return nil, nil, req_err
    end
    httpc:set_keepalive()
    return body, headers
end

local function request_cert(self, domain, timeout)
    -- Get the certificate from backend cert server.
    local cert_json, headers, req_err = make_request(self, { path = "/cert/" .. domain }, timeout, true)
    if not (cert_json and headers) or req_err then
        return nil, nil, nil, nil, req_err
    end

    -- Convert certificate from PEM to DER format.
    local cert_der, pkey_der, der_err
    cert_der, der_err = ssl.cert_pem_to_der(cert_json["cert"])
    if not cert_der or der_err then
        return nil, nil, nil, nil, "failed to convert certificate from PEM to DER: " .. (der_err or "nil")
    end
    pkey_der, der_err = ssl.priv_key_pem_to_der(cert_json["pkey"])
    if not pkey_der or der_err then
        return nil, nil, nil, nil, "failed to convert private key from PEM to DER: " .. (der_err or "nil")
    end

    return cert_der, pkey_der, cert_json["ttl"], cert_json["expire_at"]
end

local function get_cert(self, domain)
    local cache = ngx.shared.ssl_certs_cache
    local bak_cert_key = "cert:" .. domain
    local bak_pkey_key = "pkey:" .. domain
    local cert_key = "cert:" .. domain .. ":latest"
    local pkey_key = "pkey:" .. domain .. ":latest"
    local lock_key = "lock:cert:" .. domain
    local lock_exptime = 120  -- seconds

    local cert, cache_err = cache:get(cert_key)
    if cache_err then
        return nil, nil, "failed to get cert cache: " .. cache_err
    end
    local pkey, cache_err = cache:get(pkey_key)
    if cache_err then
        return nil, nil, "failed to get pkey cache: " .. cache_err
    end
    if (cert and pkey) then
        return cert, pkey
    end

    -- Lock to prevent multiple requests for same domain.
    local lock, lock_err = _lock(lock_key, {exptime = lock_exptime, timeout = lock_exptime})
    if not lock then
        return nil, nil, lock_err
    end

    -- Check the cache again after holding the lock.
    cert, cache_err = cache:get(cert_key)
    if cache_err then
        _log_unlock(lock)
        return nil, nil, "failed to get cert cache: " .. cache_err
    end
    pkey, cache_err = cache:get(pkey_key)
    if cache_err then
        _log_unlock(lock)
        return nil, nil, "failed to get pkey cache: " .. cache_err
    end

    -- Someone has already done the work.
    if (cert and pkey) then
        _log_unlock(lock)
        return cert, pkey
    end

    -- We are the first, request certificate from backend server.
    local cert, pkey, ttl, expire_at, req_err = request_cert(self, domain, lock_exptime - 10)
    if (cert and pkey) then
        -- Cache the newly requested certificate as long living backup and short-living cache.
        -- Backup cert (even expired) is preferred than self-signed if backend server is not available.
        local ok, cache_err = _safe_set_cache({
            [ bak_cert_key ] = { cert },
            [ bak_pkey_key ] = { pkey },
            [ cert_key ] = { cert, ttl },
            [ pkey_key ] = { pkey, ttl }
        })
        if not ok then
            ngx.log(ngx.ERR, cache_err)
        end
    else
        -- Since certificate renewal happens far before expired on backend server,
        -- most probably the previous backup certificate is valid, we use it if it exists.
        -- This avoids further requests within next cache period triggering certificate
        -- requests to backend, which may slow down nginx and rise up pressure on busy site.
        -- Also we consider an recently-expired certificate is more friendly to our users
        -- than fallback to self-signed certificate.
        cert, cache_err = cache:get(bak_cert_key)
        if cache_err then
            ngx.log(ngx.ERR, "failed to get backup cert cache: ", cache_err)
        else
            pkey, cache_err = cache:get(bak_pkey_key)
            if cache_err then
                ngx.log(ngx.ERR, "failed to get backup pkey cache: ", cache_err)
            end
        end
    end

    -- Now we can release the lock.
    _log_unlock(lock)

    if not (cert and pkey) then
        return nil, nil, req_err
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

local function request_stapling(self, domain, timeout)
    -- Get OCSP stapling from backend cert server.
    local stapling, headers, req_err = make_request(self, { path = "/ocsp/" .. domain }, timeout, false)
    if req_err then
        return nil, nil, nil, err
    end

    -- Parse TTL from response header, default 10 minutes if absent for any reason.
    local ttl = tonumber(headers["X-TTL"] or 600)
    local expire_at = tonumber(headers["X-Expire-At"] or 600)
    return stapling, ttl, expire_at
end

local function get_stapling(self, domain)
    local cache = ngx.shared.ssl_certs_cache
    local bak_stapling_key = "stapling:" .. domain
    local stapling_key = "stapling:" .. domain .. ":latest"
    local lock_key = "lock:stapling:" .. domain
    local lock_exptime = 10  -- seconds

    local stapling, cache_err = cache:get(stapling_key)
    if cache_err then
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end
    if stapling then
        return stapling
    end

    -- Lock to prevent multiple requests for same domain.
    local lock, lock_err = _lock(lock_key, {exptime = lock_exptime, timeout = lock_exptime})
    if not lock then
        return nil, lock_err
    end

    -- Check the cache again after holding the lock.
    stapling, cache_err = cache:get(stapling_key)
    if cache_err then
        _log_unlock(lock)
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end
    if stapling then
        _log_unlock(lock)
        return stapling
    end

    -- We are the first, request and cache OCSP stapling from backend server.
    local stapling, ttl, expire_at, req_err = request_stapling(self, domain, lock_exptime - 2)
    if stapling then
        -- Consider time deviation, expire the backup 10 seconds before expiration.
        local backup_ttl = expire_at - ngx.time() - 10
        if backup_ttl > 0 then
            local ok, cache_err = cache:set(bak_stapling_key, stapling, backup_ttl)
            if not ok then
                ngx.log(ngx.ERR, "failed to set backup stapling cache: ", cache_err)
            end
        end
        local ok, cache_err = cache:set(stapling_key, stapling, ttl)
        if not ok then
            ngx.log(ngx.ERR, "failed to set stapling cache: ", cache_err)
        end
    else
        -- In case of backend failure, check backup for unexpired response.
        stapling, cache_err = cache:get(bak_stapling_key)
        if cache_err then
            ngx.log(ngx.ERR, "failed to get backup stapling cache: ", cache_err)
        end
    end

    -- Release the lock.
    _log_unlock(lock)

    if not stapling then
        return nil, req_err
    end
    return stapling
end

local function set_stapling(self, stapling)
    -- Set the OCSP stapling response.
    local ok, err = ocsp.set_ocsp_status_resp(stapling)
    if not ok then
        return false, "failed to set OCSP stapling: " .. err
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
        local ok, err = set_cert(self, cert, pkey)
        if not ok then
            ngx.log(ngx.ERR, domain, ": ", err)
            return
        end
    else
        ngx.log(ngx.ERR, domain, ": ", err)
        return
    end

    -- TODO: check whether OCSP servers available

    local stapling, err = get_stapling(self, domain)
    if stapling then
        local ok, err = set_stapling(self, stapling)
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
    local domain, domain_err = ssl.server_name()
    if domain_err then
        ngx.log(ngx.WARN, "failed to get ssl.server_name (SNI not suspported?): ", domain_err)
    end
    if not domain or domain == "" then
        domain = ngx.var.host
        if not domain or domain == "" then
            ngx.log(ngx.ERR, "could not determine domain from either ssl.server_name nor ngx.var.host")
            ngx.exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    if not self.options["allow_domain"](domain) then
        ngx.log(ngx.NOTICE, domain, ": domain not allowed")
        ngx.exit(ngx.HTTP_NOT_FOUND)
    end

    -- Proxy challenge request to backend cert server.
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, conn_err = httpc:connect(self.options["backend_host"], self.options["backend_port"])
    if not ok then
        ngx.log(ngx.ERR, domain, ": failed to connect backend server: ", conn_err)
        ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end

    httpc:set_timeout(2000)
    httpc:proxy_response(httpc:proxy_request())
    httpc:set_keepalive()
end

return _M
