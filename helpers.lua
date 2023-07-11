--
-- helpers.lua
--
-- This is a file called at every request by the `access.lua` file. It contains
-- a set of useful functions related to HTTP and LDAP.
--

module('helpers', package.seeall)

local cache = ngx.shared.cache
local conf = config.get_config()
local Logging = require("logging")
local jwt = require("vendor.luajwtjitsi.luajwtjitsi")
local cipher = require('openssl.cipher')
local mime = require("mime")

local appender = function(self, level, message)

  -- Output to log file
  local fp = io.open(log_file, "a")
  local str = string.format("[%-6s%s] %s\n", level:upper(), os.date(), message)
  fp:write(str)
  fp:close()
  
  return true
end

local logger = Logging.new(appender)
--logger:setLevel(logger.DEBUG)   -- FIXME


-- Import Perl regular expressions library
local rex = require "rex_pcre"

local is_logged_in = false

function refresh_config()
    conf = config.get_config()
end

function get_config()
    return conf
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

-- Read a FS stored file
function read_file(file)
    local f = io.open(file, "rb")
    if not f then return false end
    local content = f:read("*all")
    f:close()
    return content
end


-- Lua has no sugar :D
function is_in_table(t, v)
    for key, value in ipairs(t) do
        if value == v then return key end
    end
end


-- Get the index of a value in a table
function index_of(t,val)
    for k,v in ipairs(t) do
        if v == val then return k end
    end
end


-- Test whether a string starts with another
function string.starts(String, Start)
    if not String then
        return false
    end
    return string.sub(String, 1, string.len(Start)) == Start
end


-- Test whether a string ends with another
function string.ends(String, End)
   return End=='' or string.sub(String, -string.len(End)) == End
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


-- Validate authentification
--
-- Check if the session cookies are set, and rehash server + client information
-- to match the session hash.
--
function check_authentication()

    local token = ngx.var["cookie_" .. conf["cookie_name"]]
    
    decoded, err = jwt.verify(token, "HS256", cookie_secret)
    
    if err ~= nil then
        -- FIXME : log an authentication error to be caught by fail2ban ? or should it happen somewhere else ? (check the old code)
        authUser = nil
        authPasswordEnc = nil
        is_logged_in = false
        return is_logged_in
    end

    -- cf. src/authenticators/ldap_ynhuser.py in YunoHost to see how the cookie is actually created
    authUser = decoded["user"]
    authPasswordEnc = decoded["pwd"]
    is_logged_in = true

    -- Gotta update authUser and is_logged_in
    return is_logged_in
end

-- Extract the user password from cookie,
-- needed to create the basic auth header
function decrypt_user_password()
    -- authPasswordEnc is actually a string formatted as <password_enc_b64>|<iv_b64>
    -- For example: ctl8kk5GevYdaA5VZ2S88Q==|yTAzCx0Gd1+MCit4EQl9lA==
    -- The password is encoded using AES-256-CBC with the IV being the right-side data
    local password_enc_b64, iv_b64 = authPasswordEnc:match("([^|]+)|([^|]+)")
    local password_enc = mime.unb64(password_enc_b64)
    local iv = mime.unb64(iv_b64)
    return cipher.new('aes-256-cbc'):decrypt(cookie_secret, iv):final(password_enc)
end

-- Check whether a user is allowed to access a URL using the `permissions` directive
-- of the configuration file
function has_access(permission, user)
    user = user or authUser

    if permission == nil then
        logger:debug("No permission matching request for "..ngx.var.uri)
        return false
    end

    -- Public access
    if user == nil or permission["public"] then
        user = user or "A visitor"
        logger:debug(user.." tries to access "..ngx.var.uri.." (corresponding perm: "..permission["id"]..")")
        return permission["public"]
    end

    logger:debug("User "..user.." tries to access "..ngx.var.uri.." (corresponding perm: "..permission["id"]..")")

    -- The user has permission to access the content if he is in the list of allowed users
    if element_is_in_table(user, permission["users"]) then
        logger:debug("User "..user.." can access "..ngx.var.host..ngx.var.uri..uri_args_string())
        return true
    else
        logger:debug("User "..user.." cannot access "..ngx.var.uri)
        return false
    end
end

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

-- Set the authentication headers in order to pass credentials to the
-- application underneath.
function set_basic_auth_header(user)
    local user = user or authUser
    -- Set `Authorization` header to enable HTTP authentification
    ngx.req.set_header("Authorization", "Basic "..ngx.encode_base64(
      user..":"..decrypt_user_password()
    ))
end


-- Set cookie and redirect (needed to properly set cookie)
function redirect(url)
    logger:debug("Redirecting to "..url)
    -- For security reason we don't allow to redirect onto unknown domain
    -- And if `uri_args.r` contains line break, someone is probably trying to
    -- pass some additional headers

    -- This should cover the following cases:
    -- https://malicious.domain.tld/foo/bar
    -- http://malicious.domain.tld/foo/bar
    -- https://malicious.domain.tld:1234/foo
    -- malicious.domain.tld/foo/bar
    -- (/foo/bar, in which case no need to make sure it's prefixed with https://)
    if not string.starts(url, "/") and not string.starts(url, "http://") and not string.starts(url, "https://") then
        url = "https://"..url
    end
    local is_known_domain = string.starts(url, "/")
    for _, domain in ipairs(conf["domains"]) do
        if is_known_domain then
          break
        end
        -- Replace - character to %- because - is a special char for regex in lua
        domain = string.gsub(domain, "%-","%%-")
        is_known_domain = is_known_domain or url:match("^https?://"..domain.."/?") ~= nil
    end
    if string.match(url, "(.*)\n") or not is_known_domain then
        logger:debug("Unauthorized redirection to "..url)
        url = conf.portal_url
    end
    return ngx.redirect(url)
end


-- Set cookie and go on with the response (needed to properly set cookie)
function pass()
    logger:debug("Allowing to pass through "..ngx.var.uri)

    -- When we are in the SSOwat portal, we need a default `content-type`
    if string.ends(ngx.var.uri, "/")
    or string.ends(ngx.var.uri, ".html")
    or string.ends(ngx.var.uri, ".htm")
    then
        ngx.header["Content-Type"] = "text/html"
    end

    return
end
