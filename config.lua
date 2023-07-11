--
-- config.lua
--
-- This file loads the configuration from config files or default values.
--

module('config', package.seeall)

local lfs = require "lfs"
local json = require "json"

local config_attributes = nil
local config_persistent_attributes = nil

local conf = {}

function get_cookie_secret()

    local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
    local conf_ = json.decode(conf_file:read("*all"))
    conf_file:close()

    local cookie_secret_path = conf_["cookie_secret_file"] or "/etc/yunohost/.ssowat_cookie_secret"
    local cookie_secret_file = assert(io.open(cookie_secret_path, "r"), "Cookie secret file is missing")
    local cookie_secret = cookie_secret_file:read("*all")
    cookie_secret_file:close()

    return cookie_secret
end



function compare_attributes(file_attributes1, file_attributes2)
    if file_attributes1 == nil and file_attributes2 == nil then
        return true
    elseif file_attributes1 == nil and file_attributes2 ~= nil or file_attributes1 ~= nil and file_attributes2 == nil then
        return false
    end
    return file_attributes1["modification"] == file_attributes2["modification"] and file_attributes1["size"] == file_attributes2["size"]
end

function get_config()

    -- Get config files attributes (timestamp modification and size)
    local new_config_attributes = lfs.attributes(conf_path, {"modification", "size"})
    local new_config_persistent_attributes = lfs.attributes(conf_path..".persistent", {"modification", "size"})

    if compare_attributes(new_config_attributes, config_attributes) and compare_attributes(new_config_persistent_attributes, config_persistent_attributes) then
        return conf
    -- If the file is being written, its size may be 0 and reloading fails, return the last valid config
    elseif new_config_attributes == nil or new_config_attributes["size"] == 0 then
        return conf
    end

    -- If the timestamp of the modification or the size is different, reload the configuration.
    config_attributes = new_config_attributes
    config_persistent_attributes = new_config_persistent_attributes
    
    local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
    conf = json.decode(conf_file:read("*all"))
    conf_file:close()

    -- Load additional rules from the `.persistent` configuration file.
    -- The `.persistent` file contains rules that will overwrite previous rules.
    -- It typically enables you to set custom rules.
    local persistent_conf_file = io.open(conf_path..".persistent", "r")
    if persistent_conf_file ~= nil then
        perm_conf = json.decode(persistent_conf_file:read("*all"))
        persistent_conf_file:close()
        for k, v in pairs(perm_conf) do

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
        portal_path               = "/ssowat/",
        local_portal_domain       = "yunohost.local",
        domains                   = { conf["portal_domain"], "yunohost.local" },
        skipped_urls              = {},
        logging                   = "fatal", -- Only log fatal messages by default (so apriori nothing)
        permissions               = {}
    }


    -- Load default values unless they are set in the configuration file.
    for param, default_value in pairs(default_conf) do
        conf[param] = conf[param] or default_value
    end


    -- If you access the SSO by a local domain, change the portal domain to
    -- avoid unwanted redirections.
    if ngx.var.host == conf["local_portal_domain"] then
        conf["portal_domain"] = conf["local_portal_domain"]
    end


    -- Build portal full URL out of the configuration values
    conf.portal_url = "https://"..
                      conf["portal_domain"]..
                      conf["portal_path"]


    -- Always skip the portal to avoid redirection looping.
    table.insert(conf["permissions"]["core_skipped"]["uris"], conf["portal_domain"]..conf["portal_path"])

    return conf
end
