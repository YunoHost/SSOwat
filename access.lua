--
-- access.lua
--
-- This file is executed at every request on a protected domain or server.
-- You just have to read this file normally to understand how and when the
-- request is handled: redirected, forbidden, bypassed or served.
--

-- Get the `cache` persistent shared table
local cache = ngx.shared.cache

-- Import helpers
local hlp = require "helpers"

-- Initialize and get configuration
hlp.refresh_config()
local conf = hlp.get_config()

-- Just a note for the client to know that he passed through the SSO
ngx.header["X-SSO-WAT"] = "You've just been SSOed"

local is_logged_in = hlp.check_authentication()

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
            hlp.logger:debug("Requested URI is in redirected_urls")
            detect_redirection(redirect_url)
        end
    end
end

if conf["redirected_regex"] then
    for regex, redirect_url in pairs(conf["redirected_regex"]) do
        if hlp.match(ngx.var.host..ngx.var.uri..hlp.uri_args_string(), regex)
        or hlp.match(ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri..hlp.uri_args_string(), regex)
        or hlp.match(ngx.var.uri..hlp.uri_args_string(), regex) then
            hlp.logger:debug("Requested URI is in redirected_regex")
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

--
--
-- 5. APPLY PERMISSION
--
--

-- 1st case : client has access

if hlp.has_access(permission) then

    if is_logged_in then
        -- If the user is logged in, refresh_cache
        --hlp.refresh_user_cache()

        -- If Basic Authorization header are enable for this permission,
        -- add it to the response
        if permission["auth_header"] then
            hlp.set_basic_auth_header()
        end
    end

    return hlp.pass()

-- 2nd case : no access ... redirect to portal / login form
else

    if is_logged_in then
        return hlp.redirect(conf.portal_url)
    else
        local back_url = "https://" .. ngx.var.host .. ngx.var.uri .. hlp.uri_args_string()
        return hlp.redirect(conf.portal_url.."?r="..ngx.encode_base64(back_url))
    end
end
