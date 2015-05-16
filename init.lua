--
-- init.lua
--
-- This is the initialization file of SSOwat. It is called once at the Nginx
-- server's start.
-- Consequently, all the variables declared (along with libraries and 
-- translations) in this file will be *persistent* from one HTTP request to
-- another.
--

-- Remove prepending '@' & trailing 'init.lua'
script_path = string.sub(debug.getinfo(1).source, 2, -9)

-- Include local libs in package.path
package.path = package.path .. ";"..script_path.."?.lua"

-- Load libraries
local json = require "json"
local lualdap = require "lualdap"
local math = require "math"
local hige = require "hige"
local lfs = require "lfs"
local socket = require "socket"
local config = require "config"

-- Persistent shared table
flashs = {}
i18n = {}

-- Efficient function to get a random string
function random_string ()
    math.randomseed( tonumber(tostring(socket.gettime()*10000):reverse()) )
    str = tostring(math.random()):sub(3)
    socket.sleep(1e-400)
    return str
end

-- Load translations in the "i18n" above table
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

-- You should see that in your Nginx error logs by default
ngx.log(ngx.INFO, "SSOwat ready")
