--
-- Load configuration
--
local conf_file = assert(io.open("cache.json", "r"), "Configuration file is missing")
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
function string.starts (String, Start)
   return string.sub(String, 1, string.len(Start)) == Start
end

function string.ends (String, End)
   return End=='' or string.sub(String, -string.len(End)) == End
end

function set_auth_cookie (user)
    local maxAge = 60 * 60 * 24 * 7 -- 1 week
    local expire = ngx.req.start_time() + maxAge
    local hash = ngx.md5(auth_key..
               "|" ..ngx.var.remote_addr..
               "|"..user..
               "|"..expire)
    local cookie_str = "; Domain=."..ngx.var.host..
                       "; Path=/"..
                       "; Max-Age="..maxAge
    ngx.header["Set-Cookie"] = {
        "YnhAuthUser="..user..cookie_str,
        "YnhAuthHash="..hash..cookie_str,
        "YnhAuthExpire="..expire..cookie_str
    }
end

function set_token_cookie ()
    local token = tostring(math.random(111111, 999999))
    tokens[token] = token
    ngx.header["Set-Cookie"] = {
        "YnhAuthToken="..token..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    }
end

function set_redirect_cookie (redirect_url)
    ngx.header["Set-Cookie"] = {
        "YnhAuthRedirect="..redirect_url..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600"
    }
end

function delete_cookie ()
    expired_time = ngx.req.start_time() - 3600 -- expired yesterday
    ngx.header["Set-Cookie"] = {
        "YnhAuthUser=;"    ..expired_time,
        "YnhAuthHash=;"    ..expired_time,
        "YnhAuthExpire=;"  ..expired_time
    }
end

function delete_onetime_cookie ()
    expired_time = ngx.req.start_time() - 3600 -- expired yesterday
    ngx.header["Set-Cookie"] = {
        "YnhAuthToken=;"   ..expired_time,
        "YnhAuthRedirect=;"..expired_time
    }
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
    return lualdap.open_simple (
        "localhost",
        "uid=".. user ..",ou=users,dc=yunohost,dc=org",
        password
    )
end

function set_headers (user)
    ldap = lualdap.open_simple("localhost")
    for dn, attribs in ldap:search {
        base = "uid=".. user ..",ou=users,dc=yunohost,dc=org",
        scope = "base",
        sizelimit = 1,
        attrs = {"uid", "givenName", "sn", "homeDirectory", "mail"}
    } do
        for name, value in pairs (attribs) do
            ngx.header["X-YNH-".. name:upper()] = value
        end
    end
end

function display_login_form ()
    local args = ngx.req.get_uri_args()

    if args.action and args.action == 'logout' then
        -- Logout
        delete_cookie()
        return ngx.redirect(portal_url)
    else
        -- Display normal form
        set_token_cookie()
        return
    end
end

function do_login ()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()

    -- CSRF check
    local token = ngx.var.cookie_YnhAuthToken

    if token and tokens[token] then
        tokens[token] = nil

        if authenticate(args.user, args.password) then
            set_auth_cookie(args.user)
            --ngx.status = ngx.HTTP_CREATED
            --ngx.exit(ngx.HTTP_OK)

            -- Redirect to precedent page
            local redirect_url = ngx.var.cookie_YnhAuthRedirect
            if redirect_url then
	        return ngx.redirect(ngx.unescape_uri(redirect_url))
            end
        end
        return ngx.redirect(portal_url)
    end
end

function pass ()
    if not ngx.header["Content-Type"] then
        ngx.header["Content-Type"] = "text/html"
    end
    delete_onetime_cookie()
    return
end

--
-- Routing
--

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

if not ngx.var.cookie_YnhAuthRedirect and not string.ends(ngx.var.uri, "favicon.ico") then
    -- Else redirect to portal
    local back_url = ngx.escape_uri(ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri)
    set_redirect_cookie(back_url)
    return ngx.redirect(portal_url)
else
    ngx.status = ngx.HTTP_UNAUTHORIZED
    return ngx.exit(ngx.HTTP_OK)
end
