--
-- config.lua
--
-- This file loads the configuration from config files or default values.
--

module('config', package.seeall)

local lfs = require("lfs")
local json = require("json")

local config_attributes = nil
local config_persistent_attributes = nil

local conf = {}

local conf_path = "/etc/ssowat/conf.json"

function file_can_be_opened_for_reading(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

function get_cookie_secret()

    local conf_file = assert(io.open(conf_path, "r"), "Configuration file is missing")
    local conf_ = json.decode(conf_file:read("*all"))
    conf_file:close()

    local cookie_secret_path = conf_["cookie_secret_file"] or "/etc/yunohost/.ssowat_cookie_secret"

    if file_can_be_opened_for_reading(cookie_secret_path) then
        ngx.log(ngx.STDERR, "Cookie secret file doesn't exist (yet?) or can't be opened for reading. Authentication will be disabled for now.")
        return nil
    end

    local cookie_secret_file = io.open(cookie_secret_path, "r")
    if cookie_secret_file ~= nil then
        local cookie_secret = cookie_secret_file:read("*all")
        cookie_secret_file:close()
        return cookie_secret
    else
        ngx.log(ngx.STDERR, "Cookie secret file doesn't exist (yet?) or can't be opened for reading. Authentication will be disabled for now.")
        return nil
    end
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

    -- Define empty dict if conf file is empty~ish,
    -- to at least avoid miserably crashing later
    if conf["domain_portal_urls"] == nil then
        conf["domain_portal_urls"] = {}
    end
    if conf["permissions"] == nil then
        conf["permissions"] = {}
    end

    -- Always skip the portal urls to avoid redirection looping.
    for domain, portal_url in pairs(conf["domain_portal_urls"]) do
        table.insert(conf["permissions"]["core_skipped"]["uris"], portal_url)
    end

    return conf
end
