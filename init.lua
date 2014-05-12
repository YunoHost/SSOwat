-- Remove prepending '@' & trailing 'init.lua'
script_path = string.sub(debug.getinfo(1).source, 2, -9)

-- Include local libs in package.path
package.path = package.path .. ";"..script_path.."?.lua"

-- Load libraries
json = require "json"
lualdap = require "lualdap"
math = require "math"
hige = require "hige"
lfs = require "lfs"

-- Shared table
flashs = {}
login = {}
logout = {}
i18n = {}

local locale_dir = script_path.."portal/locales/"
for file in lfs.dir(locale_dir) do
    if string.sub(file, -4) == "json" then
        local lang = string.sub(file, 1, 2)
        local locale_file = io.open(locale_dir..file, "r")
        i18n[lang] = json.decode(locale_file:read("*all"))
    end
end 

-- Path of the configuration
conf_path = "/etc/ssowat/conf.json"

ngx.log(ngx.INFO, "SSOwat ready")
