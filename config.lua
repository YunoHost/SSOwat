--
-- config.lua
--
-- This file loads the configuration from config files or default values.
--

module('config', package.seeall)

function get_config()

    -- Load the configuration file
    local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
    local conf = json.decode(conf_file:read("*all"))


    -- Load additional rules from the `.persistent` configuration file.
    -- The `.persistent` file contains rules that will overwrite previous rules.
    -- It typically enables you to set custom rules.
    local persistent_conf_file = io.open(conf_path..".persistent", "r")
    if persistent_conf_file ~= nil then
        for k, v in pairs(json.decode(persistent_conf_file:read("*all"))) do

           -- If the configuration key already exists and is a table, merge it
           if conf[k] and type(v) == "table" then
               for subk, subv in pairs(v) do
                   if type(subk) == "number" then
                       table.insert(conf[k], subv)
                   else
                       conf[k][subk] = subv
                   end
               end

            -- Else just take the persistent rule's value
            else
               conf[k] = v
            end
        end
    end


    -- Default configuration values
    default_conf = {
        portal_scheme             = "https",
        portal_path               = "/ssowat/",
        local_portal_domain       = "yunohost.local",
        domains                   = { conf["portal_domain"], "yunohost.local" },
        session_timeout           = 60 * 60 * 24,     -- one day
        session_max_timeout       = 60 * 60 * 24 * 7, -- one week
        login_arg                 = "sso_login",
        ldap_host                 = "localhost",
        ldap_group                = "ou=users,dc=yunohost,dc=org",
        ldap_identifier           = "uid",
        ldap_enforce_crypt        = true,
        skipped_urls              = {},
        users                     = {},
        ldap_attributes           = {"uid", "givenname", "sn", "cn", "homedirectory", "mail", "maildrop"},
        additional_headers        = {["Remote-User"] = "uid"},
        allow_mail_authentication = true,
        default_language          = "en"
    }


    -- Load default values unless they are set in the configuration file.
    for param, default_value in pairs(default_conf) do
        conf[param] = conf[param] or default_value
    end



    -- If you access the SSO by a local domain, change the portal domain to
    -- avoid unwanted redirections.
    if ngx.var.host == conf["local_portal_domain"] then
        conf["original_portal_domain"] = conf["portal_domain"]
        conf["portal_domain"] = conf["local_portal_domain"]
    end


    -- Build portal full URL out of the configuration values
    conf.portal_url = conf["portal_scheme"].."://"..
                      conf["portal_domain"]..
                      conf["portal_path"]


    -- Always skip the portal to avoid redirection looping.
    table.insert(conf["skipped_urls"], conf["portal_domain"]..conf["portal_path"])


    -- Set the prefered language from the `Accept-Language` header
    conf.lang = ngx.req.get_headers()["Accept-Language"]

    if conf.lang then
        conf.lang = string.sub(conf.lang, 1, 2)
    end

    return conf
end
