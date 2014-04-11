--
-- Load configuration
--
cache = ngx.shared.cache
srvkey = cache:get("srvkey")
if not srvkey then
    math.randomseed(os.time())
    srvkey = tostring(math.random(1111111, 9999999))
    cache:add("srvkey", srvkey)
end
oneweek = 60 * 60 * 24 * 7
cookies = {}

-- Load conf file
local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
local conf = json.decode(conf_file:read("*all"))

-- Load additional rules 
local persistent_conf_file = io.open(conf_path..".persistent", "r")
if persistent_conf_file ~= nil then
    for k, v in pairs(json.decode(persistent_conf_file:read("*all"))) do
       -- If key already exists and is a table, merge it 
       if conf[k] and type(v) == "table" then
           for subk, subv in pairs(v) do
               if type(subk) == "number" then
                   table.insert(conf[k], subv)
               else
                   conf[k][subk] = subv
               end
           end 
        else
           conf[k] = v
	end
    end
end

local portal_url = conf["portal_scheme"].."://"..
                   conf["portal_domain"]..
                   conf["portal_path"]
table.insert(conf["skipped_urls"], conf["portal_domain"]..conf["portal_path"])

-- Dummy intructions
ngx.header["X-SSO-WAT"] = "You've just been SSOed"


--
--  Useful functions
--
function read_file(file)
    local f = io.open(file, "rb")
    if not f then return false end
    local content = f:read("*all")
    f:close()
    return content
end

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

function flash (wat, message)
    if wat == "fail"
    or wat == "win"
    or wat == "info"
    then
        flashs[wat] = message
    end
end

function set_auth_cookie (user, domain)
    local maxAge = oneweek
    local expire = ngx.req.start_time() + maxAge
    local session_key = cache:get("session_"..user)
    if not session_key then
        session_key = tostring(math.random(1111111, 9999999))
        cache:add("session_"..user, session_key)
    end
    local hash = ngx.md5(srvkey..
               "|" ..ngx.var.remote_addr..
               "|"..user..
               "|"..expire..
               "|"..session_key)
    local cookie_str = "; Domain=."..domain..
                       "; Path=/"..
                       "; Max-Age="..maxAge
    cook("SSOwAuthUser="..user..cookie_str)
    cook("SSOwAuthHash="..hash..cookie_str)
    cook("SSOwAuthExpire="..expire..cookie_str)
end

function set_redirect_cookie (redirect_url)
    cook(
        "SSOwAuthRedirect="..redirect_url..
        "; Path="..conf["portal_path"]..
        "; Max-Age=3600;"
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

function delete_redirect_cookie ()
    expired_time = "Thu, Jan 01 1970 00:00:00 UTC;"
    local cookie_str = "; Path="..conf["portal_path"]..
                       "; Max-Age="..expired_time
    cook("SSOwAuthRedirect=;" ..cookie_str)
end

function is_logged_in ()

    -- Check if cookie is set
    if  ngx.var.cookie_SSOwAuthExpire and ngx.var.cookie_SSOwAuthExpire ~= ""
    and ngx.var.cookie_SSOwAuthHash   and ngx.var.cookie_SSOwAuthHash   ~= ""
    and ngx.var.cookie_SSOwAuthUser   and ngx.var.cookie_SSOwAuthUser   ~= ""
    then
        -- Check expire time
        if (ngx.req.start_time() <= tonumber(ngx.var.cookie_SSOwAuthExpire)) then
            -- Check hash
            local session_key = cache:get("session_"..ngx.var.cookie_SSOwAuthUser)
            if session_key and session_key ~= "" then
                local hash = ngx.md5(srvkey..
                        "|"..ngx.var.remote_addr..
                        "|"..ngx.var.cookie_SSOwAuthUser..
                        "|"..ngx.var.cookie_SSOwAuthExpire..
                        "|"..session_key)
                return hash == ngx.var.cookie_SSOwAuthHash
            end
        end
    end

    return false
end

function has_access (user, url)
    user = user or ngx.var.cookie_SSOwAuthUser
    url = url or ngx.var.host..ngx.var.uri
    if not conf["users"] or not conf["users"][user] then
        return true
    end
    for u, _ in pairs(conf["users"][user]) do
        if string.starts(url, string.sub(u, 1, -2)) then return true end
    end
    return false
end

function authenticate (user, password)
    if string.find(user, "@") then
        ldap = lualdap.open_simple("localhost")
        for dn, attribs in ldap:search {
            base = "ou=users,dc=yunohost,dc=org",
            scope = "onelevel",
            sizelimit = 1,
            filter = "(mail="..user..")",
            attrs = {"uid"}
        } do
            if attribs["uid"] then
                user = attribs["uid"]
            else
                return false
            end
        end
        ldap:close()
    end
    connected = lualdap.open_simple (
        "localhost",
        "uid=".. user ..",ou=users,dc=yunohost,dc=org",
        password
    )

    cache:flush_expired()
    if connected then
        cache:add(user.."-password", password, oneweek)
        return user
    else
        return false
    end
end

function set_headers (user)
    if ngx.var.scheme ~= "https" then
        return redirect("https://"..ngx.var.http_host..ngx.var.uri)
    end
    user = user or ngx.var.cookie_SSOwAuthUser
    if not cache:get(user.."-password") then
        flash("info", "Please log in to access to this content")
        local back_url = ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri
        return redirect(portal_url.."?r="..ngx.encode_base64(back_url))
    end
    if not cache:get(user.."-uid") then
        ldap = lualdap.open_simple("localhost")
        for dn, attribs in ldap:search {
            base = "uid=".. user ..",ou=users,dc=yunohost,dc=org",
            scope = "base",
            sizelimit = 1,
            attrs = {"uid", "givenname", "sn", "cn", "homedirectory", "mail", "maildrop"}
        } do
            for k,v in pairs(attribs) do
                if type(v) == "table" then
                    for k2,v2 in ipairs(v) do
                        if k2 == 1 then cache:set(user.."-"..k, v2, oneweek) end
                        cache:set(user.."-"..k.."|"..k2, v2, oneweek)
                    end
                else
                    cache:set(user.."-"..k, v, oneweek)
                end
            end
        end
    end

    -- Set HTTP Auth header
    ngx.req.set_header("Authorization", "Basic "..ngx.encode_base64(
      user..":"..cache:get(user.."-password")
    ))

    -- Set Additional headers
    for k, v in pairs(conf["additional_headers"]) do
        ngx.req.set_header(k, cache:get(user.."-"..v))
    end

end

function get_mails(user)
    local mails = { mail = "", mailalias = {}, maildrop = {} }
    if cache:get(user.."-mail|2") then
        for _, v in ipairs({2, 3, 4, 5, 6, 7, 8, 9, 10}) do
            table.insert(mails["mailalias"], cache:get(user.."-mail|"..v))
        end
    end
    mails["mail"] = cache:get(user.."-mail")
    if cache:get(user.."-maildrop|2") then
        for _, v in ipairs({2, 3, 4, 5, 6, 7, 8, 9, 10}) do
            table.insert(mails["maildrop"], cache:get(user.."-maildrop|"..v))
        end
    end
    return mails
end

-- Yo dawg
function serve(uri)
    rel_path = string.gsub(uri, conf["portal_path"], "/")

    -- Load login.html as index
    if rel_path == "/" then
        if is_logged_in() then
            rel_path = "/info.html"
        else
            rel_path = "/login.html"
        end
    end

    -- Access to directory root: forbidden
    if string.ends(rel_path, "/") then
        return ngx.exit(403)
    end

    -- Try to get file content
    local content = read_file(script_path.."portal"..rel_path)
    if not content then
        return ngx.exit(ngx.HTTP_NOT_FOUND)
    end

    -- Extract file extension
    _, file, ext = string.match(rel_path, "(.-)([^\\/]-%.?([^%.\\/]*))$")

    -- Associate to MIME type
    mime_types = {
        html = "text/html",
        ms   = "text/html",
        js   = "text/javascript",
        map  = "text/javascript",
        css  = "text/css",
        gif  = "image/gif",
        jpg  = "image/jpeg",
        png  = "image/png",
        svg  = "image/svg+xml",
        ico  = "image/vnd.microsoft.icon",
        woff = "application/x-font-woff",
        json = "application/json"
    }

    -- Set Content-Type
    if mime_types[ext] then
        ngx.header["Content-Type"] = mime_types[ext]
    else
        ngx.header["Content-Type"] = "text/plain"
    end

    -- Render as mustache
    if ext == "html" then
        local data = get_data_for(file)
        local rendered = hige.render(read_file(script_path.."portal/header.ms"), data)
        rendered = rendered..hige.render(content, data)
        content = rendered..hige.render(read_file(script_path.."portal/footer.ms"), data)
    elseif ext == "ms" then
        local data = get_data_for(file)
        content = hige.render(content, data)
    elseif ext == "json" then
        local data = get_data_for(file)
        content = json.encode(data)
    end

    -- Reset flash messages
    flashs["fail"] = nil
    flashs["win"] = nil
    flashs["info"] = nil

    -- Ain't nobody got time for cache
    ngx.header["Cache-Control"] = "no-cache"
    ngx.say(content)
    return ngx.exit(ngx.HTTP_OK)
end

function get_data_for(view)
    local user = ngx.var.cookie_SSOwAuthUser
    local data = {}

    if view == "login.html" then
        data["title"] = "YunoHost Login"

    elseif view == "info.html" then
        set_headers(user)

        local mails = get_mails(user)
        data = {
            title     = user.." <small>"..cache:get(user.."-cn").."</small>",
            connected = true,
            uid       = user,
            cn        = cache:get(user.."-cn"),
            mail      = mails["mail"],
            mailalias = mails["mailalias"],
            maildrop  = mails["maildrop"],
            app = {}
        }

        for url, name in pairs(conf["users"][user]) do
            table.insert(data["app"], { url = url, name = name })
        end

    elseif view == "password.html" then

        data = {
            title     = "Change password",
            connected = true
        }

    elseif view == "edit.html" then
        set_headers(user)

        local mails = get_mails(user)
        data = {
            title     = "Edit "..user,
            connected = true,
            uid       = user,
            sn        = cache:get(user.."-sn"),
            givenName = cache:get(user.."-givenName"),
            mail      = mails["mail"],
            mailalias = mails["mailalias"],
            maildrop  = mails["maildrop"]
        }

    elseif view == "panel.ms" then
        data = { app = {} }
        for url, name in pairs(conf["users"][user]) do
            table.insert(data["app"], { url = url, name = name })
        end
    elseif view == "ynhpanel.json" then
        local mails = get_mails(user)
        data = {
            app = {},
            user = {
              uid = user,
              name = cache:get(user..'-cn'),
              givenName = cache:get(user..'-givenName'),
              surname = cache:get(user..'-sn'),
              mail = mails['mail']
            },
            portal_url = portal_url
        }
        for url, name in pairs(conf["users"][user]) do
            table.insert(data["app"], { url = url, name = name })
        end
    end

    data['flash_fail'] = {flashs["fail"]}
    data['flash_win']  = {flashs["win"] }
    data['flash_info'] = {flashs["info"]}
    return data
end

function do_edit ()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()

    if is_logged_in() and args
    then
        ngx.status = ngx.HTTP_CREATED
        local user = ngx.var.cookie_SSOwAuthUser

        -- Change password
        if string.ends(ngx.var.uri, "password.html") then
            if args.currentpassword
            and args.currentpassword == cache:get(user.."-password")
            then
                if args.newpassword == args.confirm then
                    local dn = "uid="..user..",ou=users,dc=yunohost,dc=org"
                    local ldap = lualdap.open_simple("localhost", dn, args.currentpassword)
                    local password = "{SHA}"..ngx.encode_base64(ngx.sha1_bin(args.newpassword))
                    if ldap:modify(dn, {'=', userPassword = password }) then
                        flash("win", "Password successfully changed")
                        cache:set(user.."-password", args.newpassword, oneweek)
                        return redirect(portal_url.."info.html")
                    else
                        flash("fail", "An error occured on password changing")
                    end
                else
                    flash("fail", "New passwords don't match")
                end
             else
                flash("fail", "Actual password is wrong")
             end
             return redirect(portal_url.."password.html")

         -- Edit user informations
         elseif string.ends(ngx.var.uri, "edit.html") then
             if args.givenName and args.sn and args.mail then

                 local mailalias = {}
                 if args["mailalias[]"] and type(args["mailalias[]"]) == "table" then
                     mailalias = args["mailalias[]"]
                 end

                 local maildrop = {}
                 if args["maildrop[]"] and type(args["maildrop[]"]) == "table" then
                     maildrop = args["maildrop[]"]
                 end

                 local mail_pattern = "[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?"

                 table.insert(mailalias, 1, args.mail)
                 for k, mail in ipairs(mailalias) do
                     if mail == "" then
                         table.remove(mailalias, k)
                     elseif not mail:match(mail_pattern) then
                         flash("fail", "Invalid mail address: "..mail)
                         return redirect(portal_url.."edit.html")
                     else
                         local domains = conf["domains"]
                         local domain_valid = false
                         for _, domain in ipairs(domains) do
                             if string.ends(mail, "@"..domain) then
                                 domain_valid = true
                                 break
                             end
                         end
                         if not domain_valid then
                             flash("fail", "Invalid domain for mail "..mail)
                             return redirect(portal_url.."edit.html")
                         end
                     end
                 end

                 for k, mail in ipairs(maildrop) do
                     if mail == "" then
                         table.remove(maildrop, k)
                     elseif not mail:match(mail_pattern) then
                         flash("fail", "Invalid mail forward address: "..mail)
                         return redirect(portal_url.."edit.html")
                     end
                 end
                 table.insert(maildrop, 1, user)

                 local dn = "uid="..user..",ou=users,dc=yunohost,dc=org"
                 local ldap = lualdap.open_simple("localhost", dn, cache:get(user.."-password"))
                 local cn = args.givenName.." "..args.sn
                 if ldap:modify(dn, {'=', cn    = cn,
                                          gecos = cn,
                                          givenName = args.givenName,
                                          sn = args.sn,
                                          mail = mailalias,
                                          maildrop = maildrop })
                 then
                     cache:delete(user.."-uid")
                     set_headers(user) -- Ugly trick to reload cache
                     flash("win", "Informations updated")
                     return redirect(portal_url.."info.html")
                 else
                     flash("fail", "An error occured on user saving")
                 end
             else
                 flash("fail", "Missing required fields")
             end
             return redirect(portal_url.."edit.html")
         end
    end
end

function do_login ()
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    local uri_args = ngx.req.get_uri_args()

    user = authenticate(args.user, args.password)
    if user then
        ngx.status = ngx.HTTP_CREATED
        set_auth_cookie(user, ngx.var.host)
        if uri_args.r then
            return redirect(portal_url.."?r="..uri_args.r)
        else
            return redirect(portal_url)
        end
    else
        ngx.status = ngx.HTTP_UNAUTHORIZED
        flash("fail", "Wrong username/password combination")
        return redirect(portal_url)
    end
end

function do_logout()
    local args = ngx.req.get_uri_args()
    if is_logged_in() then
        cache:delete("session_"..ngx.var.cookie_SSOwAuthUser)
        flash("info", "Logged out")
        return redirect(portal_url)
    end
end

function redirect (url)
    ngx.header["Set-Cookie"] = cookies
    return ngx.redirect(url)
end

function pass ()
    delete_redirect_cookie()
    ngx.req.set_header("Set-Cookie", cookies)
    return
end


--------------------------------------------------
-- Routing
--

-- Logging in
--   i.e. http://mydomain.org/~sso~a6e5320f

if string.match(ngx.var.uri, "~sso~%d+$") then
    cda_key = string.sub(ngx.var.uri, -7)
    if login[cda_key] then
        set_auth_cookie(login[cda_key], ngx.var.host)
        login[cda_key] = nil
        return redirect(string.gsub(ngx.var.uri, "~sso~%d+$", ""))
    end
end


-- Portal
--   i.e. http://mydomain.org/ssowat/*

if ngx.var.host == conf["portal_domain"]
   and string.starts(ngx.var.uri, string.sub(conf["portal_path"], 1, -2))
then
    if ngx.var.request_method == "GET" then

        -- http://mydomain.org/ssowat
        if ngx.var.uri.."/" == conf["portal_path"] then
            return redirect(portal_url)
        end

        uri_args = ngx.req.get_uri_args()
        if uri_args.action and uri_args.action == 'logout' then
            -- Logout
            return do_logout()

        elseif is_logged_in() and uri_args.r then
            cda_key = tostring(math.random(1111111, 9999999))
            login[cda_key] = ngx.var.cookie_SSOwAuthUser
            return redirect(ngx.decode_base64(uri_args.r).."~sso~"..cda_key)

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
            flash("info", "Please log in to access to this content")
            return redirect(portal_url)
        end

    elseif ngx.var.request_method == "POST" then

        -- CSRF protection
        if string.starts(ngx.var.http_referer, portal_url) then
            if string.ends(ngx.var.uri, conf["portal_path"].."password.html")
            or string.ends(ngx.var.uri, conf["portal_path"].."edit.html")
            then
               return do_edit()
            else
               return do_login()
            end
        else
            -- Redirect to portal
            flash("fail", "Please log in from the portal")
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
        if url == ngx.var.host..ngx.var.uri 
        or url == ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri
        or url == ngx.var.uri then
            detect_redirection(redirect_url)
        end
    end
end

if conf["redirected_regex"] then
    for regex, redirect_url in pairs(conf["redirected_regex"]) do
        if string.match(ngx.var.host..ngx.var.uri, regex)
        or string.match(ngx.var.scheme.."://"..ngx.var.host..ngx.var.uri, regex) 
        or string.match(ngx.var.uri, regex) then
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
        if (string.starts(ngx.var.host..ngx.var.uri, url)
        or  string.starts(ngx.var.uri, url))
        and not is_protected() then
            return pass()
        end
    end
end

if conf["skipped_regex"] then
    for _, regex in ipairs(conf["skipped_regex"]) do
        if (string.match(ngx.var.host..ngx.var.uri, regex)
        or  string.match(ngx.var.uri, regex))
        and not is_protected() then
            return pass()
        end
    end
end



-- Unprotected urls
--  i.e. http://mydomain.org/no_protection+headers/

if conf["unprotected_urls"] then
    for _, url in ipairs(conf["unprotected_urls"]) do
        if (string.starts(ngx.var.host..ngx.var.uri, url)
        or  string.starts(ngx.var.uri, url))
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
        if (string.match(ngx.var.host..ngx.var.uri, regex)
        or  string.match(ngx.var.uri, regex))
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
        serve("/ynhsso/assets/js/ynhpanel.js")
    end
    if string.match(ngx.var.uri, "^/ynhpanel.css$") then
        serve("/ynhsso/assets/css/ynhpanel.css")
    end
    if string.match(ngx.var.uri, "^/ynhpanel.json$") then
        serve("/ynhsso/assets/js/ynhpanel.json")
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

flash("info", "Please log in to access to this content")
local back_url = ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.uri
return redirect(portal_url.."?r="..ngx.encode_base64(back_url))

