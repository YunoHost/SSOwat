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

-- Initialize and get configuration
local conf = config.get_config()

-- Import helpers
local hlp = require "helpers"

-- Load logging module
local logger = require("log")

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
if (ngx.var.host == conf["portal_domain"] or hlp.is_logged_in())
   and hlp.string.starts(ngx.var.uri, string.sub(conf["portal_path"], 1, -2))
then

    -- `GET` method will serve a portal file
    if ngx.var.request_method == "GET" then

        -- Force portal scheme
        if ngx.var.scheme ~= conf["portal_scheme"] then
            logger.debug("Redirecting to "..conf.portal_url.."Cross-domain authentication: "..user.." connected on "..ngx.var.host)
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
        elseif hlp.is_logged_in() and uri_args.r then
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
            conf = config.get_config()
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
        elseif hlp.is_logged_in()
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
-- 3. Redirected URLs
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


local longest_protected_match = hlp.longest_url_path(hlp.get_matches("protected")) or ""
local longest_skipped_match = hlp.longest_url_path(hlp.get_matches("skipped")) or ""
local longest_unprotected_match = hlp.longest_url_path(hlp.get_matches("unprotected")) or ""

logger.debug("longest skipped "..longest_skipped_match)
logger.debug("longest unprotected "..longest_unprotected_match)
logger.debug("longest protected "..longest_protected_match)

--
-- 4. Skipped URLs
--
-- If the URL matches one of the `skipped_urls` in the configuration file,
-- it means that the URL should not be protected by the SSO and no header
-- has to be sent, even if the user is already authenticated.
--

if longest_skipped_match ~= ""
and string.len(longest_skipped_match) >= string.len(longest_protected_match) 
and string.len(longest_skipped_match) > string.len(longest_unprotected_match) then
    logger.debug("Skipping "..ngx.var.uri)
    return hlp.pass()
end

--
-- 5. Specific files (used in YunoHost)
--
-- We want to serve specific portal assets right at the root of the domain.
--
-- For example: `https://mydomain.org/ynhpanel.js` will serve the
-- `/yunohost/sso/assets/js/ynhpanel.js` file.
--

function scandir(directory, callback)
    -- use find (and not ls) to list only files recursively and with their full path relative to the asked directory
    local pfile = io.popen('find "'..directory..'" -type f')
    for filename in pfile:lines() do
        callback(filename)
    end
    pfile:close()
end

function serveAsset(shortcut, full)
  if string.match(ngx.var.uri, "^"..shortcut.."$") then
      logger.debug("Serving static asset "..full)
      hlp.serve("/yunohost/sso/assets/"..full, "static_asset")
  end
end

function serveThemeFile(filename)
  serveAsset("/ynhtheme/"..filename, "themes/"..conf.theme.."/"..filename)
end

function serveYnhpanel()
    logger.debug("Serving ynhpanel")

    -- serve ynhpanel files
    serveAsset("/ynh_portal.js", "js/ynh_portal.js")
    serveAsset("/ynh_overlay.css", "css/ynh_overlay.css")
    -- serve theme's files
    -- FIXME? I think it would be better here not to use an absolute path
    -- but I didn't succeed to figure out where is the current location of the script
    -- if you call it from "portal/assets/themes/" the ls fails
    scandir("/usr/share/ssowat/portal/assets/themes/"..conf.theme, serveThemeFile)
end

--
-- 6. Unprotected URLs
--
-- If the URL matches one of the `unprotected_urls` in the configuration file,
-- it means that the URL should not be protected by the SSO *but* headers have
-- to be sent if the user is already authenticated.
--
-- It means that you can let anyone access to an app, but if a user has already
-- been authenticated on the portal, he can have his authentication headers
-- passed to the app.
--

if longest_unprotected_match ~= ""
and string.len(longest_unprotected_match) > string.len(longest_protected_match) then
    if hlp.is_logged_in() then
        serveYnhpanel()

        hlp.set_headers()
    end
    logger.debug(ngx.var.uri.." is in unprotected_urls")
    return hlp.pass()
end

if hlp.is_logged_in() then
    serveYnhpanel()

    -- If user has no access to this URL, redirect him to the portal
    if not hlp.has_access() then
        return hlp.redirect(conf.portal_url)
    end

    -- If the user is authenticated and has access to the URL, set the headers
    -- and let it be
    hlp.set_headers()
    return hlp.pass()
end


--
-- 7. Basic HTTP Authentication
--
-- If the `Authorization` header is set before reaching the SSO, we want to
-- match user and password against the user database.
--
-- It allows you to bypass the cookie-based procedure with a per-request
-- authentication. Very usefull when you are trying to reach a specific URL
-- via cURL for example.
--

local auth_header = ngx.req.get_headers()["Authorization"]

if auth_header then
    _, _, b64_cred = string.find(auth_header, "^Basic%s+(.+)$")
    _, _, user, password = string.find(ngx.decode_base64(b64_cred), "^(.+):(.+)$")
    user = hlp.authenticate(user, password)
    if user then
        logger.debug("User got authenticated through basic auth")
        -- If user has no access to this URL, redirect him to the portal
        if not hlp.has_access(user) then
           return hlp.redirect(conf.portal_url)
        end

        hlp.set_headers(user)

        -- If user has no access to this URL, redirect him to the portal
        if not hlp.has_access(user) then
            return hlp.redirect(conf.portal_url)
        end

        return hlp.pass()
    end
end


--
-- 8. Redirect to login
--
-- If no previous rule has matched, just redirect to the portal login.
-- The default is to protect every URL by default.
--

-- Only display this if HTTPS. For HTTP, we can't know if the user really is
-- logged in or not, because the cookie is available only in HTTP...
if ngx.var.scheme == "https" then
    hlp.flash("info", hlp.t("please_login"))
end

-- Force the scheme to HTTPS. This is to avoid an issue with redirection loop
-- when trying to access http://main.domain.tld/ (SSOwat finds that user aint
-- logged in, therefore redirects to SSO, which redirects to the back_url, which
-- redirect to SSO, ..)
logger.debug("No rule found for "..ngx.var.uri..". By default, redirecting to portal")
local back_url = "https://" .. ngx.var.host .. ngx.var.uri .. hlp.uri_args_string()
return hlp.redirect(conf.portal_url.."?r="..ngx.encode_base64(back_url))
