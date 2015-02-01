--
-- access.lua
--
-- This file is executed at every request on a protected domain or server.
-- You just have to read this file normally to understand how and when the
-- request is handled: redirected, forbidden, bypassed or served.
--


-- Initialize configuration
require "config"

-- Initialize the non-persistent cookie table
cookies = {}

-- Import helpers
hlp = require "helpers"

-- Just a note for the client to know that he passed through the SSO
ngx.header["X-SSO-WAT"] = "You've just been SSOed"


--
-- 1. LOGIN
--
-- example: https://mydomain.org/?sso_login=a6e5320f
--
-- If the `sso_login` URI argument is set, try a cross-domain authentication
-- with the token passed as argument
--
if ngx.var.host ~= conf["portal_domain"] and ngx.var.request_method == "GET" then
    uri_args = ngx.req.get_uri_args()
    if uri_args[conf.login_arg] then
        cda_key = uri_args[conf.login_arg]
        if login[cda_key] then
            set_auth_cookie(login[cda_key], ngx.var.host)
            ngx.log(ngx.NOTICE, "Cross-domain authentication: "..login[cda_key].." connected on "..ngx.var.host)
            login[cda_key] = nil
            uri_args[conf.login_arg] = nil
            return redirect(ngx.var.uri..uri_args_string(uri_args))
        end
    end
end


--
-- 2. PORTAL
--
-- example: https://mydomain.org/ssowat*
--
-- If the URL matches the portal URL, serve a portal file or proceed to a
-- portal operations
--
if ngx.var.host == conf["portal_domain"]
   and string.starts(ngx.var.uri, string.sub(conf["portal_path"], 1, -2))
then
    if ngx.var.request_method == "GET" then

        -- Force portal scheme
        if ngx.var.scheme ~= conf["portal_scheme"] then
            return redirect(portal_url)
        end

        -- Add a trailing `/` if not present
        if ngx.var.uri.."/" == conf["portal_path"] then
            return redirect(portal_url)
        end

        uri_args = ngx.req.get_uri_args()
        if uri_args.action and uri_args.action == 'logout' then
            -- Logout
            return do_logout()

        elseif is_logged_in() and uri_args.r then
            back_url = ngx.decode_base64(uri_args.r)
            if  not string.match(back_url, "^http[s]?://"..ngx.var.host.."/")
            and not string.match(back_url, ".*"..conf.login_arg.."=%d+$") then
                cda_key = tostring(math.random(1111111, 9999999))
                login[cda_key] = ngx.var.cookie_SSOwAuthUser
                if string.match(back_url, ".*?.*") then
                    back_url = back_url.."&"
                else
                    back_url = back_url.."?"
                end
                back_url = back_url.."sso_login="..cda_key
            end
            return redirect(back_url)

        elseif is_logged_in()                                             -- Authenticated
            or ngx.var.uri == conf["portal_path"]                         -- OR Want to serve portal login
            or (string.starts(ngx.var.uri, conf["portal_path"].."assets")
               and (not ngx.var.http_referer
                    or string.starts(ngx.var.http_referer, portal_url)))  -- OR Want to serve assets for portal login
        then
            -- Serve normal portal
            return serve(ngx.var.uri)

        else
            -- Redirect to portal
            flash("info", t("please_login"))
            return redirect(portal_url)
        end

    elseif ngx.var.request_method == "POST" then

        -- CSRF protection
        if string.starts(ngx.var.http_referer, portal_url) then
            if string.ends(ngx.var.uri, conf["portal_path"].."password.html")
            or string.ends(ngx.var.uri, conf["portal_path"].."edit.html")
            then
               return post_edit()
            else
               return post_login()
            end
        else
            -- Redirect to portal
            flash("fail", t("please_login_from_portal"))
            return redirect(portal_url)
        end
    end
end

-- Redirected urls

function detect_redirection(redirect_url)
    if string.starts(redirect_url, "http://")
    or string.starts(redirect_url, "https://") then
        return redirect(redirect_url)
    elseif  string.starts(redirect_url, "/") then
        return redirect(ngx.var.scheme.."://"..ngx.var.host..redirect_url)
    else
        return redirect(ngx.var.scheme.."://"..redirect_url)
    end
end

if conf["redirected_urls"] then
    for url, redirect_url in pairs(conf["redirected_urls"]) do
        if url == ngx.var.host..ngx.var.uri..uri_args_string()
        or url == ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..uri_args_string()
        or url == ngx.var.uri..uri_args_string() then
            detect_redirection(redirect_url)
        end
    end
end

if conf["redirected_regex"] then
    for regex, redirect_url in pairs(conf["redirected_regex"]) do
        if string.match(ngx.var.host..ngx.var.uri..uri_args_string(), regex)
        or string.match(ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..uri_args_string(), regex)
        or string.match(ngx.var.uri..uri_args_string(), regex) then
            detect_redirection(redirect_url)
        end
    end
end

-- URL that must be protected
function is_protected()
    if not conf["protected_urls"] then
        conf["protected_urls"] = {}
    end
    if not conf["protected_regex"] then
        conf["protected_regex"] = {}
    end

    for _, url in ipairs(conf["protected_urls"]) do
        if string.starts(ngx.var.host..ngx.var.uri, url)
        or string.starts(ngx.var.uri, url) then
            return true
        end
    end
    for _, regex in ipairs(conf["protected_regex"]) do
        if string.match(ngx.var.host..ngx.var.uri, regex)
        or string.match(ngx.var.uri, regex) then
            return true
        end
    end

    return false
end

-- Skipped urls
--  i.e. http://mydomain.org/no_protection/

if conf["skipped_urls"] then
    for _, url in ipairs(conf["skipped_urls"]) do
        if (string.starts(ngx.var.host..ngx.var.uri..uri_args_string(), url)
        or  string.starts(ngx.var.uri..uri_args_string(), url))
        and not is_protected() then
            return pass()
        end
    end
end

if conf["skipped_regex"] then
    for _, regex in ipairs(conf["skipped_regex"]) do
        if (string.match(ngx.var.host..ngx.var.uri..uri_args_string(), regex)
        or  string.match(ngx.var.uri..uri_args_string(), regex))
        and not is_protected() then
            return pass()
        end
    end
end



-- Unprotected urls
--  i.e. http://mydomain.org/no_protection+headers/

if conf["unprotected_urls"] then
    for _, url in ipairs(conf["unprotected_urls"]) do
        if (string.starts(ngx.var.host..ngx.var.uri..uri_args_string(), url)
        or  string.starts(ngx.var.uri..uri_args_string(), url))
        and not is_protected() then
            if is_logged_in() then
                set_headers()
            end
            return pass()
        end
    end
end

if conf["unprotected_regex"] then
    for _, regex in ipairs(conf["unprotected_regex"]) do
        if (string.match(ngx.var.host..ngx.var.uri..uri_args_string(), regex)
        or  string.match(ngx.var.uri..uri_args_string(), regex))
        and not is_protected() then
            if is_logged_in() then
                set_headers()
            end
            return pass()
        end
    end
end

-- Cookie validation
--

if is_logged_in() then
    if string.match(ngx.var.uri, "^/ynhpanel.js$") then
        serve("/yunohost/sso/assets/js/ynhpanel.js")
    end
    if string.match(ngx.var.uri, "^/ynhpanel.css$") then
        serve("/yunohost/sso/assets/css/ynhpanel.css")
    end
    if string.match(ngx.var.uri, "^/ynhpanel.json$") then
        serve("/yunohost/sso/assets/js/ynhpanel.json")
    end
    if not has_access() then
        return redirect(portal_url)
    end
    set_headers()
    return pass()
end


-- Login with HTTP Auth if credentials are brought
--

local auth_header = ngx.req.get_headers()["Authorization"]
if auth_header then
    _, _, b64_cred = string.find(auth_header, "^Basic%s+(.+)$")
    _, _, user, password = string.find(ngx.decode_base64(b64_cred), "^(.+):(.+)$")
    user = authenticate(user, password)
    if user then
        set_headers(user)
        return pass()
    end
end

-- Else redirect to portal
--

flash("info", t("please_login"))
local back_url = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.uri .. uri_args_string()
return redirect(portal_url.."?r="..ngx.encode_base64(back_url))
