-- Load libraries
cjson = require "cjson"
lualdap = require "lualdap"
math = require "math"

-- Set random key
math.randomseed(os.time())
auth_key = math.random(1111111, 9999999)

-- Shared tables
tokens = {}
redirects = {}
flashs = {}
