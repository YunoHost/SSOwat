-- Load libraries
json = require "json"
lualdap = require "lualdap"
math = require "math"

-- Set random key
math.randomseed(os.time())
srvkey = math.random(1111111, 9999999)

-- Shared table
cache = {}
login = {}
logout = {}

-- Path of the configuration
conf_path = '/etc/ssowat/conf.json'
