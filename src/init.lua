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

-- Load cookie secret
-- IMPORTANT (though to be confirmed?)
-- in this context, the code is ran as root therefore we don't have to
-- add www-data in the file permissions, which could otherwise lead
-- to comprised apps running with the www-data group to read the secret file?
local config = require("config")
COOKIE_SECRET = config.get_cookie_secret()

--
-- Init logger
--

local log_file = "/var/log/nginx/ssowat.log"

-- Make sure the log file exists and we can write in it
io.popen("touch "..log_file)
io.popen("chown www-data "..log_file)
io.popen("chmod u+w "..log_file)

local Logging = require("logging")
local appender = function(self, level, message)

  -- Output to log file
  local fp = io.open(log_file, "a")
  local str = string.format("[%-6s%s] %s\n", level:upper(), os.date(), message)
  fp:write(str)
  fp:close()

  return true
end

logger = Logging.new(appender)

function isValidLoggingLevel(level)
  local validLoggingLevel = {
    Logging.DEBUG,  -- DEBUG
    Logging.INFO,   -- INFO
    Logging.WARN,   -- WARN
    Logging.ERROR,  -- ERROR
    Logging.FATAL   -- FATAL
  }
  for i, l in ipairs(validLoggingLevel)
  do
    if l == level then
      return true
    end
  end
  return false
end
conf = config.get_config()

if conf["logging"] and isValidLoggingLevel(conf["logging"]) then
  logger:setLevel(conf["logging"])
else
  logger:setLevel(Logging.INFO) -- INFO by default
end

-- You should see that in your Nginx error logs by default
ngx.log(ngx.INFO, "SSOwat ready")
