--
-- Load configuration
--
cookies = {}
local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
local conf = json.decode(conf_file:read("*all"))
local portal_url = conf["portal_scheme"].."://"..
                   conf["portal_domain"]..
                   ":"..conf["portal_port"]..
                   conf["portal_path"]
table.insert(conf["skipped_urls"], conf["portal_domain"]..conf["portal_path"])

-- Dummy intructions
ngx.header["X-SSO-WAT"] = "You've just been SSOed"

--
--  Useful functions
--
function is_in_table (t, v)
    for key, value in ipairs(t) do
        if value == v then return key end
    end
end

function string.starts (String, Start)
   return string.sub(String, 1, string.len(Start)) == Start
end

function string.ends (String, End)
   return End=='' or string.sub(String, -string.len(End)) == End
end

function cook (cookie_str)
    table.insert(cookies, cookie_str)
end

function set_auth_cookie (user, domain)
    local maxAge = 60 * 60 * 24 * 7 -- 1 week
    local expire = ngx.req.start_time() + maxAge
    local hash = ngx.md5(auth_key..
               "|" ..ngx.var.remote_addr..
               "|"..user..
               "|"..expire)
    local cookie_str = "; Domain=."..domain..
                       "; Path=/"..
                       "; Max-Age="..maxAge
    cook("SSOwAuthUser="..user..cookie_str)
    cook("SSOwAuthHash="..hash..cookie_str)
    cook("SSOwAuthExpire="..expire..cookie_str)
end

function set_token_cookie ()
    local token = tostring(math.random(111111, 999999))
    tokens[token] = token
    cook(
        "SSOwAuthToken="..token..
        "; Domain=."..conf["portal_domain"]..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    )
end

function set_redirect_cookie (redirect_url)
    cook(
        "SSOwAuthRedirect="..redirect_url..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    )
end

function delete_cookie ()
    expired_time = "Thu, Jan 01 1970 00:00:00 UTC;"
    for _, domain in ipairs(conf["domains"]) do
        local cookie_str = "; Domain=."..domain..
                           "; Path=/"..
                           "; Max-Age="..expired_time
        cook("SSOwAuthUser=;"    ..cookie_str)
        cook("SSOwAuthHash=;"    ..cookie_str)
        cook("SSOwAuthExpire=;"  ..cookie_str)
    end
end

function delete_onetime_cookie ()
    expired_time = "Thu, Jan 01 1970 00:00:00 UTC;"
    local cookie_str = "; Path="..conf["portal_path"]..
                       "; Max-Age="..expired_time
    cook("SSOwAuthToken=;"    ..cookie_str)
    cook("SSOwAuthRedirect=;" ..cookie_str)
end


function check_cookie ()

    -- Check if cookie is set
    if  ngx.var.cookie_SSOwAuthExpire and ngx.var.cookie_SSOwAuthExpire ~= ""
    and ngx.var.cookie_SSOwAuthHash   and ngx.var.cookie_SSOwAuthHash   ~= ""
    and ngx.var.cookie_SSOwAuthUser   and ngx.var.cookie_SSOwAuthUser   ~= ""
    then
        -- Check expire time
        if (ngx.req.start_time() <= tonumber(ngx.var.cookie_SSOwAuthExpire)) then
            -- Check hash
            local hash = ngx.md5(auth_key..
                    "|"..ngx.var.remote_addr..
                    "|"..ngx.var.cookie_SSOwAuthUser..
                    "|"..ngx.var.cookie_SSOwAuthExpire)
            return hash == ngx.var.cookie_SSOwAuthHash
        end
    end

    return false
end

function authenticate (user, password)
    connected = lualdap.open_simple (
        "localhost",
        "uid=".. user ..",ou=users,dc=yunohost,dc=org",
        password
    )

    if connected and not cache[user] then
        cache[user] = { password=password }
    end

    return connected
end

function set_headers (user)
    if not cache[user]["uid"] then
        ldap = lualdap.open_simple("localhost")
        for dn, attribs in ldap:search {
            base = "uid=".. user ..",ou=users,dc=yunohost,dc=org",
            scope = "base",
            sizelimit = 1,
            attrs = {"uid", "givenName", "sn", "cn", "homeDirectory", "mail"}
        } do
            for k,v in pairs(attribs) do cache[user][k] = v end
        end
    end

    ngx.header["Auth-User"] = user
    ngx.header["Remote-User"] = user
    ngx.header["Name"] = cache[user]["cn"]
    ngx.header["Email"] = cache[user]["mail"]
    ngx.header["Authorization"] = "Basic "..ngx.encode_base64(
        cache[user]["uid"]..":"..cache[user]["password"]
    )
end

function display_login_form ()
    local args = ngx.req.get_uri_args()

    -- Redirected from another domain
    if args.r then
        local redirect_url = ngx.decode_base64(args.r)
        set_redirect_cookie(redirect_url)
        return redirect(portal_url)
    end

    if args.action and args.action == 'logout' then
        -- Logout
        delete_cookie()
        return redirect(portal_url)
    elseif ngx.var.cookie_SSOwAuthToken
    and tokens[ngx.var.cookie_SSOwAuthToken]
    then
        -- Display normal form
        return pass
    else
        -- Set token
        set_token_cookie()
        return redirect(portal_url)
    end
end

function do_login ()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()

    -- CSRF check
    local token = ngx.var.cookie_SSOwAuthToken

    if token and tokens[token] then
        tokens[token] = nil
        ngx.status = ngx.HTTP_CREATED

        if authenticate(args.user, args.password) then
            local redirect_url = ngx.var.cookie_SSOwAuthRedirect
            if not redirect_url then redirect_url = portal_url end
            connections[args.user] = {}
            connections[args.user]["redirect_url"] = redirect_url
            connections[args.user]["domains"] = {}
            for _, value in ipairs(conf["domains"]) do
                table.insert(connections[args.user]["domains"], value)
            end

            -- Connect to the first domain (self)
            return redirect(ngx.var.scheme.."://"..ngx.var.http_host.."/?ssoconnect="..args.user)
        end
    end
    return redirect(portal_url)
end

function redirect (url)
    ngx.header["Set-Cookie"] = cookies
    return ngx.redirect(url, ngx.HTTP_MOVED_PERMANENTLY)
end

function pass ()
    delete_onetime_cookie()
    ngx.header["Set-Cookie"] = cookies
    return
end

--
-- Routing
--

-- Connection
if ngx.var.request_method == "GET" then
    local args = ngx.req.get_uri_args()

    -- /?ssoconnect=user
    local user = args.ssoconnect
    if user and connections[user] then
        -- Set Authentication cookie
        set_auth_cookie(user, ngx.var.host)
        -- Remove domain from connection table
        domain_key = is_in_table(connections[user]["domains"], ngx.var.host)
        table.remove(connections[user]["domains"], domain_key)

        if table.getn(connections[user]["domains"]) == 0 then
            -- All the redirections has been made
            local redirect_url = connections[user]["redirect_url"]
            connections[user] = nil
            return redirect(ngx.unescape_uri(redirect_url))
        else
            -- Redirect to the next domain
            for _, domain in ipairs(connections[user]["domains"]) do
                return redirect(ngx.var.scheme.."://"..domain.."/?ssoconnect="..user)
            end
        end
    end
end

-- Portal
if ngx.var.host == conf["portal_domain"]
   and string.starts(ngx.var.uri, conf["portal_path"])
then
    if ngx.var.request_method == "GET" then
        return display_login_form()
    elseif ngx.var.request_method == "POST" then
        return do_login()
    end
end

-- Skipped urls
for _, url in ipairs(conf["skipped_urls"]) do
    if string.starts(ngx.var.host..ngx.var.uri, url) then
        return pass
    end
end

-- Unprotected urls
for _, url in ipairs(conf["unprotected_urls"]) do
    if string.starts(ngx.var.host..ngx.var.uri, url) then
        if check_cookie() then
            set_headers(ngx.var.cookie_SSOwAuthUser)
        end
        return pass
    end
end

-- Cookie validation
if check_cookie() then
    set_headers(ngx.var.cookie_SSOwAuthUser)
    return pass
else
    delete_cookie()
end


-- Connect with HTTP Auth if credentials are brought
local auth_header = ngx.req.get_headers()["Authorization"]
if auth_header then
    _, _, b64_cred = string.find(auth_header, "^Basic%s+(.+)$")
    _, _, user, password = string.find(ngx.decode_base64(b64_cred), "^(.+):(.+)$")
    if authenticate(user, password) then
        set_headers(user)
        return pass
    end
end

-- Else redirect to portal
local back_url = ngx.escape_uri(ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri)
if set_redirect_cookie(back_url) then
    -- From same domain
    return redirect(portal_url)
else
    -- From another domain
    return redirect(portal_url.."?r="..ngx.encode_base64(back_url))
end
