--
-- Load configuration
--
cookies = {}
local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
local conf = json.decode(conf_file:read("*all"))
local portal_url = conf["portal_scheme"].."://"..
                   conf["main_domain"]..
                   ":"..conf["portal_port"]..
                   conf["portal_path"]
table.insert(conf["skipped_urls"], conf["main_domain"]..conf["portal_path"])

-- Dummy intructions
ngx.header["X-YNH-SSO"] = "You've just been SSOed"

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
    cook("YnhAuthUser="..user..cookie_str)
    cook("YnhAuthHash="..hash..cookie_str)
    cook("YnhAuthExpire="..expire..cookie_str)
end

function set_token_cookie ()
    local token = tostring(math.random(111111, 999999))
    tokens[token] = token
    cook(
        "YnhAuthToken="..token..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    )
end

function set_redirect_cookie (redirect_url)
    cook(
        "YnhAuthRedirect="..redirect_url..
        "; Domain=."..conf["main_domain"]..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    )
end

function delete_cookie ()
    expired_time = ngx.req.start_time() - 3600 -- expired yesterday
    cook("YnhAuthUser=;"    ..expired_time)
    cook("YnhAuthHash=;"    ..expired_time)
    cook("YnhAuthExpire=;"  ..expired_time)
end

function delete_onetime_cookie ()
    expired_time = ngx.req.start_time() - 3600 -- expired yesterday
    cook("YnhAuthToken=;"   ..expired_time)
    cook("YnhAuthRedirect=;"..expired_time)
end


function check_cookie ()

    -- Check if cookie is set
    if not ngx.var.cookie_YnhAuthExpire
    or not ngx.var.cookie_YnhAuthUser
    or not ngx.var.cookie_YnhAuthHash
    then
        return false
    end

    -- Check expire time
    if (ngx.req.start_time() >= tonumber(ngx.var.cookie_YnhAuthExpire)) then
        return false
    end

    -- Check hash
    local hash = ngx.md5(auth_key..
               "|"..ngx.var.remote_addr..
               "|"..ngx.var.cookie_YnhAuthUser..
               "|"..ngx.var.cookie_YnhAuthExpire)
    if hash ~= ngx.var.cookie_YnhAuthHash then
        return false
    end

    return true
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
            attrs = {"uid", "givenName", "sn", "homeDirectory", "mail"}
        } do
            for k,v in pairs(attribs) do cache[user][k] = v end
        end
    end

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
    elseif ngx.var.cookie_YnhAuthToken then
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
    local token = ngx.var.cookie_YnhAuthToken

    if token and tokens[token] then
        tokens[token] = nil
        ngx.status = ngx.HTTP_CREATED

        if authenticate(args.user, args.password) then
            local redirect_url = ngx.var.cookie_YnhAuthRedirect
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
if ngx.var.host == conf["main_domain"]
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
            set_headers(ngx.var.cookie_YnhAuthUser)
        end
        return pass
    end
end

-- Cookie validation
if check_cookie() then
    set_headers(ngx.var.cookie_YnhAuthUser)
    return pass
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
