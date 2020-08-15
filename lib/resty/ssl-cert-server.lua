local cjson = require "cjson"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local resty_lock = require "resty.lock"
local resty_http = require "resty.http"

local err_204_no_content = "204 no content"

local _M = { _VERSION = '0.4.0' }

function _M.new(options)
    options = options or {}

    local host, port
    if not options["backend"] then
        ngx.log(ngx.ERR, "using default backend server 127.0.0.1:8999")
        options["backend"] = "127.0.0.1:8999"
    else
        host, port = options["backend"]:match("([^:]+):(%d+)")
        if not host then
            host = options["backend"]:match("^%d[%d%.]+%d$")
            if not host then
                ngx.log(ngx.ERR, "invalid backend IP address, using default 127.0.0.1:8999")
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

local function _split_string(buf, length)
    local sep = "|"
    local result = {}
    local from, sep_idx = 1, 0
    for _ = 1, length - 1 do
        sep_idx = string.find(buf, sep, from)
        if sep_idx == from then
            table.insert(result, "")
        else
            table.insert(result, string.sub(buf, from, sep_idx - 1))
        end
        from = sep_idx + 1
    end
    table.insert(result, string.sub(buf, from))
    return result
end

local cachecert = {
    cert_der = nil,
    pkey_der = nil,
    cert_type = 0,
    fingerprint = "",
    expire_at = 0,
    refresh_at = 0,
}

function cachecert:new(obj)
    obj = obj or {}
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function cachecert:serialize()
    local sep = "|"
    local cert_b64 = ngx.encode_base64(self.cert_der)
    local pkey_b64 = ngx.encode_base64(self.pkey_der)
    return self.cert_type .. sep .. self.fingerprint .. sep .. self.expire_at .. sep .. self.refresh_at .. sep .. cert_b64 .. sep .. pkey_b64
end

function cachecert:deserialize(buf)
    -- see cachecert:serialize
    local result = _split_string(buf, 6)
    self.cert_type = tonumber(result[1]) or 0
    self.fingerprint = result[2] or ""
    self.expire_at = tonumber(result[3]) or 0
    self.refresh_at = tonumber(result[4]) or 0
    self.cert_der = ngx.decode_base64(result[5])
    self.pkey_der = ngx.decode_base64(result[6])
    return self
end

local cachestapling = {
    stapling = nil,
    expire_at = 0,
    refresh_at = 0,
}

function cachestapling:new(obj)
    obj = obj or {}
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function cachestapling:serialize()
    local sep = "|"
    return self.expire_at .. sep .. self.refresh_at .. sep .. self.stapling
end

function cachestapling:deserialize(buf)
    -- see cachestapling:serialize
    local result = _split_string(buf, 3)
    self.expire_at = tonumber(result[1]) or 0
    self.refresh_at = tonumber(result[2]) or 0
    self.stapling = result[3]
    return self
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

    local lock, lock_err = _lock(lock_key, { exptime = 1, timeout = 1 })
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
        -- Connect to backend as soon as possible, no more than 2 minutes.
        if not sleep then
            sleep = 1
        else
            sleep = sleep * 2
            if sleep > 120 then
                sleep = 120
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
        if res.status == 204 then
            req_err = err_204_no_content
        elseif res.status ~= 200 then
            req_err = "bad http status " .. res.status
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
        return nil, req_err
    end

    -- Convert certificate from PEM to DER format.
    local cert_der, pkey_der, der_err
    cert_der, der_err = ssl.cert_pem_to_der(cert_json["cert"])
    if not cert_der or der_err then
        return nil, "failed to convert certificate from PEM to DER: " .. (der_err or "nil")
    end
    pkey_der, der_err = ssl.priv_key_pem_to_der(cert_json["pkey"])
    if not pkey_der or der_err then
        return nil, "failed to convert private key from PEM to DER: " .. (der_err or "nil")
    end

    local cert = cachecert:new({
        cert_der = cert_der,
        pkey_der = pkey_der,
        cert_type = cert_json["type"],
        fingerprint = cert_json["fingerprint"],
        expire_at = cert_json["expire_at"],
        refresh_at = ngx.time() + cert_json["ttl"],
    })
    return cert
end

local function get_cert(self, domain)
    local cache = ngx.shared.ssl_certs_cache
    local cert_key = "cert:" .. domain
    local lock_key = "lock:cert:" .. domain
    local lock_exptime = 120  -- seconds

    local is_expired = false
    local cert_buf, cache_err = cache:get(cert_key)
    if cache_err then
        return nil, nil, "failed to get certificate cache: " .. cache_err
    end

    local cert
    if cert_buf then
        cert = cachecert:new():deserialize(cert_buf)
        -- cached certificate TTL not expired
        if cert.refresh_at > ngx.time() then
            return cert
        end
    end

    -- TTL expired, refresh it
    -- lock to prevent multiple requests for same demain.
    local lock, lock_err = _lock(lock_key, { exptime = lock_exptime, timeout = lock_exptime })
    if not lock then
        return nil, nil, lock_err
    end

    -- check the cache again after holding the lock.
    cert_buf, cache_err = cache:get(cert_key)
    if cache_err then
        _log_unlock(lock)
        return nil, nil, "failed to get certificate cache: " .. cache_err
    end
    -- Someone may already done the work.
    if cert_buf then
        cert = cachecert:new():deserialize(cert_buf)
        if cert.refresh_at > ngx.time() then
            _log_unlock(lock)
            return cert, is_expired
        end
    end

    -- We are the first, request or refresh certificate from backend server.
    local new_cert, req_err
    new_cert, req_err = request_cert(self, domain, lock_exptime - 10)
    if new_cert then
        -- Cache the newly requested certificate.
        cert = new_cert
        cert_buf = cert:serialize()
        local ok, cache_err, forcible = cache:set(cert_key, cert_buf)
        if forcible then
            ngx.log(ngx.ERR, "lua shared dict 'ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while adding certificate for " .. domain .. ")")
        end
        if not ok then
            ngx.log(ngx.ERR, domain, ": failed to set certificate cache: ", cache_err)
        end
    else
        -- Since certificate renewal happens far before expired on backend server,
        -- most probably the previous certificate is valid, we use it if it is available.
        -- This avoids further requests within next cache period triggering certificate
        -- requests to backend, which may slow down nginx and rise up pressure on busy site.
        -- Also we consider an recently-expired certificate is more friendly to our users
        -- than fallback to self-signed certificate.
        if cert.expire_at >= ngx.time() then
            is_expired = true
            ngx.log(ngx.ERR, domain, ": fallback to expired certificate")
        end
    end

    -- Now we can release the lock.
    _log_unlock(lock)

    return cert, is_expired, nil
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

local function request_stapling(self, domain, fingerprint, timeout)
    -- Get OCSP stapling from backend cert server.
    local path = "/ocsp/" .. domain .. "?fp=" .. fingerprint
    local resp_stapling, headers, req_err = make_request(self, { path = path }, timeout, false)
    if req_err then
        return nil, req_err
    end

    -- Parse TTL from response header, default 10 minutes if absent for any reason.
    local ttl = tonumber(headers["X-TTL"] or 600)
    local expire_at = tonumber(headers["X-Expire-At"] or 600)
    local stapling = cachestapling:new({
        stapling = resp_stapling,
        expire_at = expire_at,
        refresh_at = ngx.time() + ttl,
    })
    return stapling
end

local function get_stapling(self, domain, fingerprint)
    local cache = ngx.shared.ssl_certs_cache
    local stapling_key = "stapling:" .. domain .. ":" .. fingerprint
    local lock_key = "lock:stapling:" .. domain
    local lock_exptime = 10  -- seconds

    local stapling_buf, cache_err = cache:get(stapling_key)
    if cache_err then
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end

    local stapling
    if stapling_buf then
        stapling = cachestapling:new():deserialize(stapling_buf)
        -- cached stapling TTL not expired
        if stapling.refresh_at > ngx.time() then
            return stapling
        end
    end

    -- TTL expired, refresh it
    -- Lock to prevent multiple requests for same domain.
    local lock, lock_err = _lock(lock_key, { exptime = lock_exptime, timeout = lock_exptime })
    if not lock then
        return nil, lock_err
    end

    -- Check the cache again after holding the lock.
    stapling_buf, cache_err = cache:get(stapling_key)
    if cache_err then
        _log_unlock(lock)
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end
    if stapling_buf then
        stapling = cachestapling.new():deserialize(stapling_buf)
        _log_unlock(lock)
        return stapling
    end

    -- We are the first, request and cache OCSP stapling from backend server.
    local new_stapling, req_err
    new_stapling, req_err = request_stapling(self, domain, fingerprint, lock_exptime - 2)
    if new_stapling then
        -- Cache the newly requested stapling.
        -- Consider time deviation, expire the backup 10 seconds before expiration.
        stapling = new_stapling
        stapling_buf = stapling:serialize()
        local expire_ttl = stapling.expire_at - ngx.time() - 10
        if expire_ttl > 0 then
            local ok, cache_err, forcible = cache:set(stapling_key, stapling_buf, expire_ttl)
            if forcible then
                ngx.log(ngx.ERR, "lua shared dict 'ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while adding OCSP stapling for " .. domain .. ")")
            end
            if not ok then
                ngx.log(ngx.ERR, "failed to set OCSP stapling cache: ", cache_err)
            end
        end
    else
        -- In case of backend failure, use cached response if not expired.
        if stapling and stapling.expire_at < ngx.time() then
            stapling = nil
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
        ngx.log(ngx.WARN, "could not determine domain for request (SNI not supported?): ", (domain_err or ""))
        return
    end

    -- Check the domain is one we allow for handling SSL.
    local allow_domain = self.options["allow_domain"]
    if not allow_domain(domain) then
        ngx.log(ngx.NOTICE, domain, ": domain not allowed")
        return
    end

    local cert, is_expired, err = get_cert(self, domain)
    local has_stapling = false
    if cert then
        if (not is_expired) and cert.cert_type < 100 then
            has_stapling = true
        end
        local ok, err = set_cert(self, cert.cert_der, cert.pkey_der)
        if not ok then
            ngx.log(ngx.ERR, domain, ": ", err)
            return
        end
    else
        ngx.log(ngx.ERR, domain, ": ", err)
        return
    end

    if (not self.options["disable_stapling"]) and has_stapling then
        local stapling, err = get_stapling(self, domain, cert.fingerprint)
        if stapling then
            local ok, err = set_stapling(self, stapling.stapling)
            if not ok then
                ngx.log(ngx.ERR, domain, ": ", err)
                return
            end
        else
            ngx.log(ngx.NOTICE, domain, ": ", err)
            return
        end
    end
end

function _M.challenge_server(self)
    local domain, domain_err = ssl.server_name()
    if domain_err then
        ngx.log(ngx.WARN, "failed to get ssl.server_name (SNI not supported?): ", domain_err)
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
        ngx.log(ngx.ERR, domain, ": failed to connect backend server to proxy challenge request: ", conn_err)
        ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end

    httpc:set_timeout(2000)
    httpc:proxy_response(httpc:proxy_request())
    httpc:set_keepalive()
end

return _M
