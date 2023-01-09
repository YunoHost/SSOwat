--
-- access.lua
--
-- This file is executed at every request on a protected domain or server.
-- You just have to read this file normally to understand how and when the
-- request is handled: redirected, forbidden, bypassed or served.
--

-- Get the `cache` persistent shared table
local cache = ngx.shared.cache

-- Generate a unique token if it has not been generated yet
srvkey = cache:get("srvkey")
if not srvkey then
    srvkey = random_string()
    cache:add("srvkey", srvkey)
end

-- Import helpers
local hlp = require "helpers"

-- Initialize and get configuration
hlp.refresh_config()
local conf = hlp.get_config()

-- Load logging module
local logger = require("log")

-- Just a note for the client to know that he passed through the SSO
ngx.header["X-SSO-WAT"] = "You've just been SSOed"

local is_logged_in = hlp.refresh_logged_in()

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

        -- Use the `cache` shared table where a username is associated with
        -- a CDA key
        user = cache:get("CDA|"..cda_key)
        if user then
            hlp.set_auth_cookie(user, ngx.var.host)
            logger.info("Cross-domain authentication: "..user.." connected on "..ngx.var.host)
            cache:delete("CDA|"..cda_key)
        end

        uri_args[conf.login_arg] = nil
        return hlp.redirect(ngx.var.uri..hlp.uri_args_string(uri_args))
    end
end


--
-- 2. PORTAL
--
-- example: https://mydomain.org/ssowat*
--
-- If the URL matches the portal URL, serve a portal file or proceed to a
-- portal operation
--
if (ngx.var.host == conf["portal_domain"] or is_logged_in)
   and hlp.string.starts(ngx.var.uri, string.sub(conf["portal_path"], 1, -2))
then

    -- `GET` method will serve a portal file
    if ngx.var.request_method == "GET" then

        -- Force portal scheme
        if ngx.var.scheme ~= conf["portal_scheme"] then
            return hlp.redirect(conf.portal_url)
        end

        -- Add a trailing `/` if not present
        if ngx.var.uri.."/" == conf["portal_path"] then
            return hlp.redirect(conf.portal_url)
        end

        -- Get request arguments
        uri_args = ngx.req.get_uri_args()

        -- Logout is also called via a `GET` method
        -- TODO: change this ?
        if uri_args.action and uri_args.action == 'logout' then
            logger.debug("Logging out")
            return hlp.logout()

        -- If the `r` URI argument is set, it means that we want to
        -- be redirected (typically after a login phase)
        elseif is_logged_in and uri_args.r then
            -- Decode back url
            back_url = ngx.decode_base64(uri_args.r)

            -- If `back_url` contains line break, someone is probably trying to
            -- pass some additional headers
            if string.match(back_url, "(.*)\n") then
                hlp.flash("fail", hlp.t("redirection_error_invalid_url"))
                logger.error("Redirection url is invalid")
                return hlp.redirect(conf.portal_url)
            end

            -- Get managed domains
            local managed_domain = false
            for _, domain in ipairs(conf["domains"]) do
                local escaped_domain = domain:gsub("-", "%%-") -- escape dash for pattern matching
                if string.match(back_url, "^http[s]?://"..escaped_domain.."/") then
                    logger.debug("Redirection to a managed domain found")
                    managed_domain = true
                    break
                end
            end

            -- If redirection does not match one of the managed domains
            -- redirect to portal home page
            if not managed_domain then
                hlp.flash("fail", hlp.t("redirection_error_unmanaged_domain"))
                logger.error("Redirection to an external domain aborted")
                return hlp.redirect(conf.portal_url)
            end


            -- In case the `back_url` is not on the same domain than the
            -- current one, create a redirection with a CDA key
            local ngx_host_escaped = ngx.var.host:gsub("-", "%%-") -- escape dash for pattern matching
            if  not string.match(back_url, "^http[s]?://"..ngx_host_escaped.."/")
            and not string.match(back_url, ".*"..conf.login_arg.."=%d+$") then
                local cda_key = hlp.set_cda_key()
                if string.match(back_url, ".*?.*") then
                    back_url = back_url.."&"
                else
                    back_url = back_url.."?"
                end
                back_url = back_url.."sso_login="..cda_key
            end

            return hlp.redirect(back_url)


        -- In case we want to serve portal login or assets for portal, just
        -- serve it
        elseif is_logged_in
            or ngx.var.uri == conf["portal_path"]
            or (hlp.string.starts(ngx.var.uri, conf["portal_path"].."assets")
               and (not ngx.var.http_referer
                    or hlp.string.starts(ngx.var.http_referer, conf.portal_url)))
        then
            -- If this is an asset, enable caching
            if hlp.string.starts(ngx.var.uri, conf["portal_path"].."assets")
            then
               return hlp.serve(ngx.var.uri, "static_asset")
            else
               return hlp.serve(ngx.var.uri)
            end


        -- If all the previous cases have failed, redirect to portal
        else
            hlp.flash("info", hlp.t("please_login"))
            logger.debug("User should log in to be able to access "..ngx.var.uri)
            -- Force the scheme to HTTPS. This is to avoid an issue with redirection loop
            -- when trying to access http://main.domain.tld/ (SSOwat finds that user aint
            -- logged in, therefore redirects to SSO, which redirects to the back_url, which
            -- redirect to SSO, ..)
            local back_url = "https://" .. ngx.var.host .. ngx.var.uri .. hlp.uri_args_string()
            return hlp.redirect(conf.portal_url.."?r="..ngx.encode_base64(back_url))
        end


    -- `POST` method is basically use to achieve editing operations
    elseif ngx.var.request_method == "POST" then

        -- CSRF protection, only proceed if we are editing from the same
        -- domain
        if hlp.string.starts(ngx.var.http_referer, conf.portal_url) then
            if hlp.string.ends(ngx.var.uri, conf["portal_path"].."password.html")
            or hlp.string.ends(ngx.var.uri, conf["portal_path"].."edit.html")
            then
               logger.debug("User attempts to edit its information")
               return hlp.edit_user()
            else
               logger.debug("User attempts to log in")
               return hlp.login()
            end
        else
            -- Redirect to portal
            hlp.flash("fail", hlp.t("please_login_from_portal"))
            logger.debug("Invalid POST request not coming from the portal url...")
            return hlp.redirect(conf.portal_url)
        end
    end
end

--
-- 2 ... continued : portal assets that are available on every domains
--
-- For example: `https://whatever.org/ynhpanel.js` will serve the
-- `/yunohost/sso/assets/js/ynhpanel.js` file.
--

if is_logged_in then
    assets = {
                   ["/ynh_portal.js"] = "js/ynh_portal.js",
                   ["/ynh_userinfo.json"] = "ynh_userinfo.json",
                   ["/ynh_overlay.css"] = "css/ynh_overlay.css"
             }
    theme_dir = "/usr/share/ssowat/portal/assets/themes/"..conf.theme
    local pfile = io.popen('find "'..theme_dir..'" -not -path "*/\\.*" -type f -exec realpath --relative-to "'..theme_dir..'" {} \\;')
    for filename in pfile:lines() do
        assets["/ynhtheme/"..filename] = "themes/"..conf.theme.."/"..filename
    end
    pfile:close()

    for shortcut, full in pairs(assets) do
        if ngx.var.uri == shortcut then
            logger.debug("Serving static asset "..full)
            return hlp.serve("/yunohost/sso/assets/"..full, "static_asset")
        end
    end
end


--
-- 3. REDIRECTED URLS
--
-- If the URL matches one of the `redirected_urls` in the configuration file,
-- just redirect to the target URL/URI
--

function detect_redirection(redirect_url)
    if hlp.string.starts(redirect_url, "http://")
    or hlp.string.starts(redirect_url, "https://") then
        return hlp.redirect(redirect_url)
    elseif hlp.string.starts(redirect_url, "/") then
        return hlp.redirect(ngx.var.scheme.."://"..ngx.var.host..redirect_url)
    else
        return hlp.redirect(ngx.var.scheme.."://"..redirect_url)
    end
end

if conf["redirected_urls"] then
    for url, redirect_url in pairs(conf["redirected_urls"]) do
        if url == ngx.var.host..ngx.var.uri..hlp.uri_args_string()
        or url == ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..hlp.uri_args_string()
        or url == ngx.var.uri..hlp.uri_args_string() then
            logger.debug("Requested URI is in redirected_urls")
            detect_redirection(redirect_url)
        end
    end
end

if conf["redirected_regex"] then
    for regex, redirect_url in pairs(conf["redirected_regex"]) do
        if hlp.match(ngx.var.host..ngx.var.uri..hlp.uri_args_string(), regex)
        or hlp.match(ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..hlp.uri_args_string(), regex)
        or hlp.match(ngx.var.uri..hlp.uri_args_string(), regex) then
            logger.debug("Requested URI is in redirected_regex")
            detect_redirection(redirect_url)
        end
    end
end

--
-- 4. IDENTIFY THE RELEVANT PERMISSION
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
--

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

            local m = hlp.match(ngx_full_url, url)
            if m ~= nil and string.len(m) > string.len(longest_url_match) then
                longest_url_match = m
                permission = permission_infos
                permission["id"] = permission_name
            end
        end
    end
end


---
--- 5. CHECK CLIENT-PROVIDED AUTH HEADER (should almost never happen?)
---

if permission ~= nil then
    perm_user_remote_user_var_in_nginx_conf = permission["use_remote_user_var_in_nginx_conf"]
    if perm_user_remote_user_var_in_nginx_conf == nil or perm_user_remote_user_var_in_nginx_conf == true then
        is_logged_in_with_basic_auth = hlp.validate_or_clear_basic_auth_header_provided_by_client()

        -- NB: is_logged_in_with_basic_auth can be false, true or nil
        if is_logged_in_with_basic_auth == false then
            return ngx.exit(ngx.HTTP_UNAUTHORIZED)
        elseif is_logged_in_with_basic_auth == true then
            is_logged_in = true
        end
    end
end

--
--
-- 6. APPLY PERMISSION
--
--

-- 1st case : client has access

if hlp.has_access(permission) then

    if is_logged_in then
        -- If the user is logged in, refresh_cache
        hlp.refresh_user_cache()

        -- If Basic Authorization header are enable for this permission,
        -- add it to the response
        if permission["auth_header"] then
            hlp.set_headers()
        else
            hlp.clear_headers()
        end
    else
        hlp.clear_headers()
    end

    return hlp.pass()

-- 2nd case : no access ... redirect to portal / login form
else

    if is_logged_in then
        return hlp.redirect(conf.portal_url)
    else
        -- Only display this if HTTPS. For HTTP, we can't know if the user really is
        -- logged in or not, because the cookie is available only in HTTP...
        if ngx.var.scheme == "https" then
            hlp.flash("info", hlp.t("please_login"))
        end

        local back_url = "https://" .. ngx.var.host .. ngx.var.uri .. hlp.uri_args_string()
        return hlp.redirect(conf.portal_url.."?r="..ngx.encode_base64(back_url))
    end
end
