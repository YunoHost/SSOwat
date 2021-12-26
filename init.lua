--
-- init.lua
--
-- This is the initialization file of SSOwat. It is called once at the Nginx
-- server's start.
-- Consequently, all the variables declared (along with libraries and 
-- translations) in this file will be *persistent* from one HTTP request to
-- another.
--

-- Path of the configuration
conf_path = "/etc/ssowat/conf.json"
log_file = "/var/log/nginx/ssowat.log"

-- Remove prepending '@' & trailing 'init.lua'
script_path = string.sub(debug.getinfo(1).source, 2, -9)

-- Include local libs in package.path
package.path = package.path .. ";"..script_path.."?.lua"

-- Load libraries
local config = require "config"

-- Load cookie secret
cookie_secret = config.get_cookie_secret()

-- Make sure the log file exists and we can write in it
io.popen("touch "..log_file)
io.popen("chown www-data "..log_file)
io.popen("chmod u+w "..log_file)

-- You should see that in your Nginx error logs by default
ngx.log(ngx.INFO, "SSOwat ready")
