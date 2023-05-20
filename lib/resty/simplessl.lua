local cjson = require "cjson"
local ocsp = require "ngx.ocsp"
local ssl = require "ngx.ssl"
local resty_lock = require "resty.lock"
local resty_http = require "resty.http"
local resty_lrucache = require "resty.lrucache"

-- alias functions and variables
local ngx_log = ngx.log
local ngx_exit = ngx.exit
local ngx_time = ngx.time
local ngx_now = ngx.now
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local ngx_INFO = ngx.INFO
local ngx_NOTICE = ngx.NOTICE
local ngx_WARN = ngx.WARN
local ngx_ERR = ngx.ERR
local setmetatable = setmetatable
local string_find = string.find
local string_sub = string.sub
local table_insert = table.insert

local err_204_no_content = "204 no content"

local _M = { _VERSION = '0.6.0' }

-- We need to initialize the cache on the lua module level so that
-- it can be shared by all the requests served by each nginx worker process.
local lru_cache

local default_httpc_opts = {
    scheme    = "http",
    pool_size = 10,
}

function _M.new(options)
    local opts = options or {}

    local host, port
    if not opts.backend then
        opts.backend = "127.0.0.1:8999"
    else
        host, port = opts.backend:match("([^:]+):(%d+)")
        if not host then
            host = opts.backend:match("^%d[%d%.]+%d$")
            if not host then
                ngx_log(ngx_ERR, "invalid backend IP address, using default 127.0.0.1:8999")
                opts.backend = "127.0.0.1:8999"
            else
                opts.backend = host .. ":80"
            end
        end
    end
    host, port = opts.backend:match("([^:]+):(%d+)")
    opts.httpc_opts = opts.httpc_opts or {}
    opts.httpc_opts.host = host
    opts.httpc_opts.port = tonumber(port or 80)
    setmetatable(opts.httpc_opts, { __index = default_httpc_opts })

    if not opts.allow_domain then
        opts.allow_domain = function(domain)
            return false
        end
    end

    local err
    opts.lru_maxitems = tonumber(opts.lru_maxitems or 100)
    lru_cache, err = resty_lrucache.new(opts.lru_maxitems)
    if err then
        ngx_log(ngx_ERR, "failed to create lru cache")
    end

    ngx_log(ngx_NOTICE, "initialized simplessl with backend ", opts.backend)
    return setmetatable({ opts = opts }, { __index = _M })
end

local function _split_string(buf, length)
    local sep = "|"
    local result = {}
    local from, sep_idx = 1, 0
    for _ = 1, length - 1 do
        sep_idx = string_find(buf, sep, from)
        if sep_idx == from then
            table_insert(result, "")
        else
            table_insert(result, string_sub(buf, from, sep_idx - 1))
        end
        from = sep_idx + 1
    end
    table_insert(result, string_sub(buf, from))
    return result
end

local cachecert = {
    cert_pem    = nil,
    pkey_pem    = nil,
    cert_type   = 0,
    fingerprint = "",
    expire_at   = 0,
    refresh_at  = 0,

    cert_cdata  = nil,
    pkey_cdata  = nil,
}

function cachecert:new(obj)
    obj = obj or {}
    setmetatable(obj, self)
    self.__index = self
    return obj
end

function cachecert:serialize()
    local sep = "|"
    return self.cert_type .. sep .. self.fingerprint .. sep .. self.expire_at .. sep .. self.refresh_at .. sep .. self.cert_pem .. sep .. self.pkey_pem
end

function cachecert:deserialize(buf)
    -- see cachecert:serialize
    local result = _split_string(buf, 6)
    self.cert_type = tonumber(result[1]) or 0
    self.fingerprint = result[2] or ""
    self.expire_at = tonumber(result[3]) or 0
    self.refresh_at = tonumber(result[4]) or 0
    self.cert_pem = result[5]
    self.pkey_pem = result[6]
    return self
end

function cachecert:parse_cert_and_priv_key()
    local cert_cdata, pkey_cdata, err
    cert_cdata, err = ssl.parse_pem_cert(self.cert_pem)
    if err then
        return "failed to parse certificate: " .. err
    end
    pkey_cdata, err = ssl.parse_pem_priv_key(self.pkey_pem)
    if err then
        return "failed to parse private key: " .. err
    end
    self.cert_cdata = cert_cdata
    self.pkey_cdata = pkey_cdata
    return nil
end

local cachestapling = {
    stapling   = nil,
    expire_at  = 0,
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
        ngx_log(ngx_ERR, "failed to unlock: " .. lock_err)
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
        if ngx_now() - previous < sleep then
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
        if ngx_now() - previous < sleep then
            _log_unlock(lock, lock_key)
            return nil, "backend is in unhealthy state"
        end
    end

    -- Backend looks all right, try it.
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, conn_err = httpc:connect(self.opts.httpc_opts)
    if not ok then
        -- Block further connections to avoid slowing down nginx too much for busy website.
        -- Connect to backend as soon as possible, no more than 1 minute.
        if not sleep then
            sleep = 1
        else
            sleep = sleep * 2
            if sleep > 60 then
                sleep = 60
            end
        end
        ngx_log(ngx_ERR, "backend is in unhealthy state, block for ", sleep, " seconds")
        ok, cache_err = cache:set(failure_key, cjson.encode({ sleep = sleep, previous = ngx_now() }))
        if not ok then
            ngx_log(ngx_ERR, "failed to set backend failure status: ", cache_err)
        end
        _log_unlock(lock)
        return nil, conn_err
    end

    -- Connect backend success, clear failure status if exists.
    if failure then
        ok, cache_err = cache:delete(failure_key)
        if not ok then
            ngx_log(ngx_ERR, "failed to delete backend failure status: ", cache_err)
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
    local req_params = {
        path = "/cert/" .. domain,
    }
    local cert_json, headers, req_err = make_request(self, req_params, timeout, true)
    if not (cert_json and headers) or req_err then
        return nil, req_err
    end
    local cert = cachecert:new(
            {
                cert_pem    = cert_json["cert"],
                pkey_pem    = cert_json["pkey"],
                cert_type   = cert_json["type"],
                fingerprint = cert_json["fingerprint"],
                expire_at   = cert_json["expire_at"],
                refresh_at  = ngx_time() + cert_json["ttl"],
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
        -- the cached certificate is within TTL, use it
        if cert.refresh_at > ngx_time() then
            return cert
        end
    end

    -- TTL expired, refresh it
    -- lock to prevent multiple requests for same domain.
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
        if cert.refresh_at > ngx_time() then
            _log_unlock(lock)
            return cert, is_expired
        end
    end

    -- We are the first, request or refresh certificate from backend server.
    local new_cert, req_err
    new_cert, req_err = request_cert(self, domain, lock_exptime - 10)
    if new_cert then
        -- Cache the newly requested certificate.
        ngx_log(ngx_NOTICE, "requested certificate from backend server: " .. domain
                .. " fingerprint= " .. new_cert["fingerprint"]
                .. " expire_at= " .. new_cert["expire_at"]
                .. " refresh_at= " .. new_cert["refresh_at"])
        cert = new_cert
        cert_buf = cert:serialize()
        local ok, cache_err, forcible = cache:set(cert_key, cert_buf)
        if forcible then
            ngx_log(ngx_ERR, "lua shared dict 'ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while adding certificate for " .. domain .. ")")
        end
        if not ok then
            ngx_log(ngx_ERR, domain, ": failed to set certificate cache: ", cache_err)
        end
    else
        -- Since certificate renewal happens far before expired on backend server,
        -- most probably the previous certificate is valid, we use it if it is available.
        -- This avoids further requests within next cache period triggering certificate
        -- requests to backend, which may slow down nginx and rise up pressure on busy site.
        -- Also we consider an recently-expired certificate is more friendly to our users
        -- than fallback to self-signed certificate.
        if cert and cert.expire_at <= ngx_time() then
            is_expired = true
            ngx_log(ngx_WARN, domain, ": fallback to expired certificate")
        end
    end

    -- Now we can release the lock.
    _log_unlock(lock)

    return cert, is_expired, nil
end

local function set_cert(self, cert_cdata, pkey_cdata)
    local ok, err

    -- Clear the default fallback certificates (defined in the hard-coded nginx configuration).
    ok, err = ssl.clear_certs()
    if not ok then
        return false, "failed to clear existing (fallback) certificates: " .. err
    end

    -- Set the public certificate chain.
    ok, err = ssl.set_cert(cert_cdata)
    if not ok then
        return false, "failed to set certificate: " .. err
    end

    -- Set the private key.
    ok, err = ssl.set_priv_key(pkey_cdata)
    if not ok then
        return false, "failed to set private key: " .. err
    end

    return true
end

local function request_stapling(self, domain, fingerprint, timeout)
    -- Get OCSP stapling from backend cert server.
    local path = "/ocsp/" .. domain .. "?fp=" .. fingerprint
    local req_params = {
        path = path,
    }
    local resp_stapling, headers, req_err = make_request(self, req_params, timeout, false)
    if req_err then
        return nil, req_err
    end

    -- Parse TTL from response header, default 10 minutes if absent for any reason.
    local ttl = tonumber(headers["X-TTL"] or 600)
    local expire_at = tonumber(headers["X-Expire-At"] or 600)
    local stapling = cachestapling:new(
            {
                stapling   = resp_stapling,
                expire_at  = expire_at,
                refresh_at = ngx_time() + ttl,
            })
    return stapling
end

local function get_stapling(self, domain, fingerprint)
    local shm_cache = ngx.shared.ssl_certs_cache
    local stapling_key = "stapling:" .. domain .. ":" .. fingerprint
    local lock_key = "lock:stapling:" .. domain
    local lock_exptime = 10  -- seconds

    local stapling_buf, cache_err = shm_cache:get(stapling_key)
    if cache_err then
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end

    local stapling
    if stapling_buf then
        stapling = cachestapling:new():deserialize(stapling_buf)
        -- the cached stapling is within TTL, use it
        if stapling.refresh_at > ngx_time() then
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
    stapling_buf, cache_err = shm_cache:get(stapling_key)
    if cache_err then
        _log_unlock(lock)
        return nil, "failed to get OCSP stapling cache: " .. cache_err
    end
    if stapling_buf then
        stapling = cachestapling:new():deserialize(stapling_buf)
        if stapling.refresh_at > ngx_time() then
            _log_unlock(lock)
            return stapling
        end
    end

    -- We are the first, request and cache OCSP stapling from backend server.
    local new_stapling, req_err
    new_stapling, req_err = request_stapling(self, domain, fingerprint, lock_exptime - 2)
    if new_stapling then
        -- Cache the newly requested stapling.
        -- Consider time deviation, expire the backup 10 seconds before expiration.
        ngx_log(ngx.NOTICE, "requested stapling from backend server: " .. domain
                .. " fingerprint= " .. fingerprint
                .. " expire_at= " .. new_stapling["expire_at"]
                .. " refresh_at= " .. new_stapling["refresh_at"])
        stapling = new_stapling
        stapling_buf = stapling:serialize()
        local expire_ttl = stapling.expire_at - ngx_time() - 10
        if expire_ttl > 0 then
            local ok, cache_err, forcible = shm_cache:set(stapling_key, stapling_buf, expire_ttl)
            if forcible then
                ngx_log(ngx_ERR, "lua shared dict 'ssl_certs_cache' might be too small - consider increasing its size (old entries were removed while adding OCSP stapling for " .. domain .. ")")
            end
            if not ok then
                ngx_log(ngx_ERR, "failed to set OCSP stapling cache: ", cache_err)
            end
        end
    else
        -- In case of backend failure, use cached response if not expired.
        if stapling and stapling.expire_at < ngx_time() then
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

local function get_cert_from_lru_cache(domain)
    local cert_key = "cert:" .. domain
    return lru_cache:get(cert_key)
end

local function set_cert_to_lru_cache(domain, cert)
    local ttl = cert.refresh_at - ngx_time()
    if ttl > 0 then
        local cert_key = "cert:" .. domain
        lru_cache:set(cert_key, cert, ttl)
    end
end

function _M.ssl_certificate(self)
    local domain, domain_err = ssl.server_name()
    if not domain or domain_err then
        ngx_log(ngx_INFO, "could not determine domain for request (SNI not supported?): ", (domain_err or ""))
        return
    end

    -- Check the domain is one we allow for handling SSL.
    if not self.opts.allow_domain(domain) then
        ngx_log(ngx_INFO, domain, ": domain not allowed")
        return
    end

    local cert = get_cert_from_lru_cache(domain)
    local has_stapling, is_expired
    local err
    if not cert then
        cert, is_expired, err = get_cert(self, domain)
    end

    -- Missed from LRU cache, and got from shared memory or backend.
    if cert and (not cert.cert_cdata) then
        err = cert:parse_cert_and_priv_key()
        if err then
            ngx_log(ngx_ERR, domain, ": ", err)
            return
        end

        -- From now on, the certificate and private key PEM are not needed
        -- anymore, drop them to save some memory space for LRU cache.
        cert.cert_pem = nil
        cert.pkey_pem = nil

        -- Cache the parsed cdata to LRU cache.
        if not is_expired then
            set_cert_to_lru_cache(domain, cert)
        end
    end

    -- Got from LRU cache, the certificate may be expired.
    if cert then
        if (not is_expired) and cert.cert_type < 100 then
            has_stapling = true
        end
        local ok, set_err = set_cert(self, cert.cert_cdata, cert.pkey_cdata)
        if not ok then
            ngx_log(ngx_ERR, domain, ": ", set_err)
            return
        end
    else
        -- No cached certificate is available, fallback to the default
        -- certificate configured in the configuration file.
        if err then
            ngx_log(ngx_ERR, domain, ": ", err)
        end
        ngx_log(ngx_WARN, domain, ": fallback to configured default certificate")
        return
    end

    if self.opts.disable_stapling or (not has_stapling) then
        return
    end

    -- Since the ocsp library supports only DER format, it doesn't make much
    -- sense to use LRU cache here, so we don't use it for OCSP stapling.
    local stapling
    stapling, err = get_stapling(self, domain, cert.fingerprint)
    if stapling then
        local ok, set_err = set_stapling(self, stapling.stapling)
        if not ok then
            ngx_log(ngx_ERR, domain, ": ", set_err)
            return
        end
    else
        ngx_log(ngx_NOTICE, domain, ": ", err)
        return
    end
end

function _M.challenge_server(self)
    local domain, domain_err = ssl.server_name()
    if domain_err then
        ngx_log(ngx_INFO, "could not get ssl.server_name (SNI not supported?): ", domain_err)
    end
    if not domain or domain == "" then
        domain = ngx.var.host
        if not domain or domain == "" then
            ngx_log(ngx_INFO, "could not determine domain from either ssl.server_name nor ngx.var.host")
            ngx_exit(ngx.HTTP_BAD_REQUEST)
        end
    end
    if not self.opts.allow_domain(domain) then
        ngx_log(ngx_INFO, domain, ": domain not allowed")
        ngx_exit(ngx.HTTP_NOT_FOUND)
    end

    -- Proxy challenge request to backend cert server.
    local httpc = resty_http.new()
    httpc:set_timeout(500)
    local ok, conn_err = httpc:connect(self.opts.httpc_opts)
    if not ok then
        ngx_log(ngx_ERR, domain, ": failed to connect backend server to proxy challenge request: ", conn_err)
        ngx_exit(ngx.HTTP_BAD_GATEWAY)
    end

    httpc:set_timeout(2000)
    httpc:proxy_response(httpc:proxy_request())
    httpc:set_keepalive()
end

return _M
