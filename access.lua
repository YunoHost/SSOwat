--
-- access.lua
--
-- This file is executed at every request on a protected domain or server.
--

-- Just a note for the client to know that he passed through the SSO
ngx.header["X-SSO-WAT"] = "You've just been SSOed"

-- Misc imports
local jwt = require("vendor.luajwtjitsi.luajwtjitsi")
local cipher = require('openssl.cipher')
local rex = require("rex_pcre")

-- ###########################################################################
--     0. Misc helpers because Lua has no sugar ...
-- ###########################################################################

-- Get configuration (we do this here, the conf is re-read every time unless
-- the file's timestamp didnt change)
local config = require("config")
local conf = config.get_config()

-- Cache expensive calculations
local cache = ngx.shared.cache

-- Hash a string using hmac_sha512, return a hexa string
function cached_jwt_verify(data, method, secret)
    res = cache:get(data)
    if res == nil then
        logger:debug("Result not found in cache, checking login")
        -- Perform expensive calculation
        decoded, err = jwt.verify(data, "HS256", cookie_secret)
        if not decoded then
            logger:error(err)
            return nil, nil, err
        end
        -- As explained in set_basic_auth_header(), user and hashed password do not contain ':'
        -- And cache cannot contain tables, so we use "user:password" format
        cached = decoded["user"]..":"..decoded["pwd"]
        cache:set(data, cached, 120)
        logger:debug("Result saved in cache")
        return decoded["user"], decoded["pwd"], err
    else
        logger:debug("Result found in cache")
        user, pwd = res:match("([^:]+):(.*)")
        return user, pwd, nil
    end
end

-- The 'match' function uses PCRE regex as default
-- If '%.' is found in the regex, we assume it's a LUA regex (legacy code)
-- 'match' returns the matched text.
function match(s, regex)
    if not string.find(regex, '%%%.') then
        return rex.match(s, regex)
    else
        return string.match(s,regex)
    end
end

-- Test whether a string starts with another
function string.starts(String, Start)
    if not String then
        return false
    end
    return string.sub(String, 1, string.len(Start)) == Start
end

-- Convert a table of arguments to an URI string
function uri_args_string(args)
    if not args then
        args = ngx.req.get_uri_args()
    end
    String = "?"
    for k,v in pairs(args) do
        String = String..tostring(k).."="..tostring(v).."&"
    end
    return string.sub(String, 1, string.len(String) - 1)
end

-- ###########################################################################
--     1. AUTHENTICATION
--  Check wether or not this is a logged-in user
--  This is not run immediately but only if:
--  - the app is not public
--  - and/or auth_headers is enabled for this app
-- ###########################################################################

function check_authentication()

    -- cf. src/authenticators/ldap_ynhuser.py in YunoHost to see how the cookie is actually created

    local cookie = ngx.var["cookie_" .. conf["cookie_name"]]
    if cookie == nil then
        return false, nil, nil
    end

    user, pwd, err = cached_jwt_verify(cookie, "H256", cookie_secret)

    -- FIXME : maybe also check that the cookie was delivered for the requested domain (or a parent?)

    -- FIXME : we might want also a way to identify expired/invalidated cookies,
    -- e.g. a user that got deleted after being logged in, or a user that logged out ...

    if err ~= nil then
        return false, nil, nil
    else
        return true, user, pwd
    end
end

-- ###########################################################################
--      2. REDIRECTED URLS
--  If the URL matches one of the `redirected_urls` in the configuration file,
--  just redirect to the target URL/URI
-- ###########################################################################

function convert_to_absolute_url(redirect_url)
    if string.starts(redirect_url, "http://")
    or string.starts(redirect_url, "https://") then
        return redirect_url
    elseif string.starts(redirect_url, "/") then
        return ngx.var.scheme.."://"..ngx.var.host..redirect_url
    else
        return ngx.var.scheme.."://"..redirect_url
    end
end

if conf["redirected_urls"] then
    for url, redirect_url in pairs(conf["redirected_urls"]) do
        if url == ngx.var.host..ngx.var.uri..uri_args_string()
        or url == ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..uri_args_string()
        or url == ngx.var.uri..uri_args_string() then
            logger:debug("Found in redirected_urls, redirecting to "..url)
            ngx.redirect(convert_to_absolute_url(redirect_url))
        end
    end
end

if conf["redirected_regex"] then
    for regex, redirect_url in pairs(conf["redirected_regex"]) do
        if match(ngx.var.host..ngx.var.uri..uri_args_string(), regex)
            or match(ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..uri_args_string(), regex)
            or match(ngx.var.uri..uri_args_string(), regex) then
            logger:debug("Found in redirected_regex, redirecting to "..url)
            ngx.redirect(convert_to_absolute_url(redirect_url))
        end
    end
end

-- ###########################################################################
--      3. IDENTIFY PERMISSION MATCHING THE REQUESTED URL
--
-- In particular, the conf is filled with permissions such as:
--
--        "foobar": {
--            "auth_header": false,
--            "label": "Foobar permission",
--            "public": false,
--            "show_tile": true,
--            "uris": [
--                "yolo.test/foobar",
--                "re:^[^/]*/%.well%-known/foobar/.*$",
--            ],
--            "users": ["alice", "bob"]
--        }
--
--
-- And we find the best matching permission by trying to match the request uri
-- against all the uris rules/regexes from the conf and keep the longest matching one.
-- ###########################################################################

permission = nil
longest_url_match = ""

ngx_full_url = ngx.var.host..ngx.var.uri

for permission_name, permission_infos in pairs(conf["permissions"]) do
    if next(permission_infos['uris']) ~= nil then
        for _, url in pairs(permission_infos['uris']) do
            if string.starts(url, "re:") then
                url = string.sub(url, 4, string.len(url))
            end
            -- We want to match the beginning of the url
            if not string.starts(url, "^") then
                url = "^"..url
            end

            local m = match(ngx_full_url, url)
            if m ~= nil and string.len(m) > string.len(longest_url_match) then
                longest_url_match = m
                permission = permission_infos
                permission["id"] = permission_name
            end
        end
    end
end

-- ###########################################################################
--     4. CHECK USER HAS ACCESS
--   Either because the permission is set as "public: true",
--   Or because the logged-in user is listed in the "users" list of the perm
-- ###########################################################################

function element_is_in_table(element, table)
    if table then
        for _, el in pairs(table) do
            if el == element then
                return true
            end
        end
    end

    return false
end

-- Check whether the app is public access
function check_public_access(permission)
    if permission == nil then
        logger:debug("No permission matching request for "..ngx.var.uri.." ... Assuming access is denied")
        return false
    end

    if permission["public"] then
        logger:debug("Someone tries to access "..ngx.var.uri.." (corresponding perm: "..permission["id"]..")")
        return true
    end
end

-- Check whether a user is allowed to access a URL using the `permissions` directive
-- of the configuration file
function check_has_access(permission)

    -- Public access
    if authUser == nil or permission["public"] then
        user = authUser or "A visitor"
        logger:debug(user.." tries to access "..ngx.var.uri.." (corresponding perm: "..permission["id"]..")")
        return permission["public"]
    end

    logger:debug("User "..authUser.." tries to access "..ngx.var.uri.." (corresponding perm: "..permission["id"]..")")

    -- The user has permission to access the content if he is in the list of allowed users
    if element_is_in_table(authUser, permission["users"]) then
        logger:debug("User "..authUser.." can access "..ngx.var.host..ngx.var.uri..uri_args_string())
        return true
    else
        logger:debug("User "..authUser.." cannot access "..ngx.var.uri)
        return false
    end
end

if check_public_access(permission) then
    has_access = true
else
    is_logged_in, authUser, authPasswordEnc = check_authentication()
    has_access = check_has_access(permission)
end

-- ###########################################################################
--     5. CLEAR USER-PROVIDED AUTH HEADER
--
--   Which could be spoofing attempts
--   Unfortunately we can't yolo-clear them on every route because some
--   apps use legit basic auth mechanism ...
--
--   "Remote user" refers to the fact that Basic Auth headers is coupled to
--   the $remote_user var in nginx, typically used by PHP apps
-- ###########################################################################

if permission ~= nil and ngx.req.get_headers()["Authorization"] ~= nil then
    perm_user_remote_user_var_in_nginx_conf = permission["use_remote_user_var_in_nginx_conf"]
    if perm_user_remote_user_var_in_nginx_conf == nil or perm_user_remote_user_var_in_nginx_conf == true then
        -- Ignore if not a Basic auth header
        -- otherwise, we interpret this as a Auth header spoofing attempt and clear it
        local auth_header_from_client = ngx.req.get_headers()["Authorization"]
        _, _, b64_cred = string.find(auth_header_from_client, "^Basic%s+(.+)$")
        if b64_cred ~= nil then
            ngx.req.clear_header("Authorization")
        end
    end
end

-- ###########################################################################
--     6. EFFECTIVELY PASS OR DENY ACCESS
--
--  If the user has access (either because app is public OR logged in + authorized)
--      -> pass + possibly inject the Basic Auth header on the fly such that the app can know which user is logged in
--
--  Otherwise, the user can't access
--      -> either because not logged in at all, in that case, redirect to the portal WITH a callback url to redirect to after logging in
--      -> or because user is logged in, but has no access .. in that case just redirect to the portal
-- ###########################################################################

function set_basic_auth_header()

    -- cf. https://en.wikipedia.org/wiki/Basic_access_authentication

    -- authPasswordEnc is actually a string formatted as <password_enc_b64>|<iv_b64>
    -- For example: ctl8kk5GevYdaA5VZ2S88Q==|yTAzCx0Gd1+MCit4EQl9lA==
    -- The password is encoded using AES-256-CBC with the IV being the right-side data
    -- cf. src/authenticators/ldap_ynhuser.py in YunoHost to see how the cookie is actually created
    local password_enc_b64, iv_b64 = authPasswordEnc:match("([^|]+)|([^|]+)")
    local password_enc = ngx.decode_base64(password_enc_b64)
    local iv = ngx.decode_base64(iv_b64)
    local password = cipher.new('aes-256-cbc'):decrypt(cookie_secret, iv):final(password_enc)

    -- Set `Authorization` header to enable HTTP authentification
    ngx.req.set_header("Authorization", "Basic "..ngx.encode_base64(
        authUser..":"..password
    ))
end

-- 1st case : client has access
if has_access then
    -- If Basic Authorization header are enable for this permission,
    -- check if the user is actually logged in...
    if permission["auth_header"] then
        if is_logged_in == nil then
            -- Login check was not performed yet because the app is public
            logger:debug("Checking authentication because the app requires auth_header")
            is_logged_in, authUser, authPasswordEnc = check_authentication()
        end
        if is_logged_in then
            -- add it to the response
            set_basic_auth_header()
        end
    end

    -- Pass
    logger:debug("Allowing to pass through "..ngx.var.uri)
    return

-- 2nd case : no access ... redirect to portal / login form
else

    portal_domain = conf["domain_portal_urls"][ngx.var.host]
    if portal_domain == nil then
        logger:debug("Domain " .. ngx.var.host .. " is not configured for SSOWat")
        ngx.status = 400
        ngx.header.content_type = "plain/text"
        ngx.say("Unmanaged domain: " .. ngx.var.host)
        return
    end
    portal_url = "https://" .. portal_domain
    logger:debug("Redirecting to portal : " .. portal_url)

    if is_logged_in then
        return ngx.redirect(portal_url)
    else
        local back_url = "https://" .. ngx.var.host .. ngx.var.uri .. uri_args_string()

        -- User ain't logged in, redirect to the portal where we expect the user to login,
        -- then be redirected to the original URL by the portal, encoded as base64
        --
        -- NB. for security reason, the client/app handling the callback should check
        -- that the back URL is legit, i.e it should be on the same domain (or a subdomain)
        -- than the portal. Otherwise, a malicious actor could create a deceptive link
        -- that would in fact redirect to a different domain, tricking the user that may
        -- not realize this.
        return ngx.redirect(portal_url.."?r="..ngx.encode_base64(back_url))
    end
end
