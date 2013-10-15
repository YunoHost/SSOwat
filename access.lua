-- Load configuration
local conf_file = assert(io.open("cache.json", "r"), "Configuration file is missing")
local conf = cjson.decode(conf_file:read("*all"))
local portal_url = conf["portal_scheme"].."://"..
                   conf["main_domain"]..
                   ":"..conf["portal_port"]..
                   conf["portal_path"]
table.insert(conf["skipped_urls"], conf["main_domain"]..conf["portal_path"])

-- Dummy intructions
ngx.header["X-YNH-SSO"] = "You've just been SSOed"

-- Useful functions
function string.starts (String, Start)
   return string.sub(String, 1, string.len(Start)) == Start
end

function set_cookie (user)
    local maxAge = 60 * 60 * 24 * 7 -- 1 week
    local expire = ngx.req.start_time() + maxAge
    local hash = ngx.md5(auth_key..
               "|" ..ngx.var.remote_addr..
               "|"..user..
               "|"..expire)
    local cookie_str = "; Domain=."..conf["main_domain"]..
                       "; Path="..conf["portal_path"]..
                       "; Max-Age="..maxAge
    ngx.header["Set-Cookie"] = {
        "YnhAuthUser="..user..cookie_str,
        "YnhAuthHash="..hash..cookie_str,
        "YnhAuthExpire="..expire..cookie_str
    }
end

function delete_cookie ()
    expired_time = gx.req.start_time() - 3600 -- expired yesterday
    ngx.header["Set-Cookie"] = {
        "YnhAuthUser=;"..expired_time,
        "YnhAuthHash=;"..expired_time,
        "YnhAuthExpire=;"..expired_time
    }
end

function check_cookie ()
    -- Check if cookie is set
    if not ( ngx.var.cookie_YnhAuthExpire and
             ngx.var.cookie_YnhAuthUser and
             ngx.var.cookie_YnhAuthHash)
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
               "|"..YnhAuthExpire)
    if (hash ~= ngx.var.cookie_YnhAuthHash) then
        return false
    end

    return true
end

function authenticate (user, password)
    return lualdap.open_simple (
        "localhost",
        "uid=".. args.user ..",ou=users,dc=yunohost,dc=org",
        args.password
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
    token = tostring(math.random(111111, 999999))
    tokens[token] = token

    -- Store the redirect URL
    if args.r then
        redirects[token] = ngx.unescape_uri(ngx.decode_base64(args.r))
    end

    if args.action and args.action == 'logout' then
        -- Logout
        delete_cookie()
        return ngx.redirect(portal_url)
    else
        -- Display normal form
        ngx.req.set_uri_args(token)
        return
    end
end

function do_login ()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()

    -- CSRF check
    if args.token and tokens[args.token] then
        local token = tokens[args.token]
        tokens[args.token] = nil

        if authenticate(args.user, args.password) then
            set_cookie(args.user)

            -- Redirect to precedent page
            if redirects[token] then
                local redirect_url = redirects[token]
                redirects[token] = nil
                return ngx.redirect(redirect_url)
            end
        end
        return ngx.redirect(portal_url)
    end
end

-- Portal route
if ngx.var.host == conf["main_domain"]
   and string.starts(ngx.var.uri, conf["portal_path"])
then
    if ngx.req.get_method() == "GET" then
        return display_login_form()
    elseif ngx.req.get_method() == "POST" then
        return do_login()
    end
end

-- Skipped urls
for _, url in ipairs(conf["skipped_urls"]) do
    if ngx.var.host..ngx.var.uri == url then
        return
    end
end

-- Unprotected urls
for _, url in ipairs(conf["unprotected_urls"]) do
    if ngx.var.host..ngx.var.uri == url then
        if check_cookie() then
            set_headers(ngx.var.cookie_YnhAuthUser)
        end
        return
    end
end

-- Cookie validation
if check_cookie() then
    set_headers(ngx.var.cookie_YnhAuthUser)
    return
end

-- Connect with HTTP Auth if credentials are brought
local auth_header = ngx.req.get_headers()["Authorization"]
if auth_header then
    _, _, b64_cred = string.find(auth_header, "^Basic%s+(.+)$")
    _, _, user, password = string.find(ngx.decode_base64(b64_cred), "^(.+):(.+)$")
    if authenticate(user, password) then
        set_headers(user)
        return
    end
end

-- Else redirect to portal
local back_url = ngx.encode_base64(ngx.escape_uri(ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri))
return ngx.redirect(portal_url.."?r="..back_url)
