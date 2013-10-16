-- Load libraries
json = require "json"
lualdap = require "lualdap"
math = require "math"

-- Set random key
math.randomseed(os.time())
auth_key = math.random(1111111, 9999999)

-- Shared table
tokens = {}
cache = {}
connections = {}

-- Path of the configuration
conf_path = 'conf.json'
