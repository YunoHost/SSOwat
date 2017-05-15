import sys
import hashlib
import hmac

key = sys.argv[1]
message = sys.argv[2]

result = hmac.new(key, digestmod=hashlib.sha512)
result.update(message)
print result.hexdigest()
