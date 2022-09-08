# TeamItaly CTF 2022

## Lazy platform (70 solves)

_I'm too lazy to implement the decryption of the ciphertexts, so I'll just give you what you need and you'll do the rest._

### Solution

In this challenge we generate the keys and the IVs of the cihertext using a non-secure random source, that is python's random module.
So we can store all the values generated from python and then crack its generator using the `randcrack` library and predict the values of the key and IV that will be used to encrypt the flag

### Exploit

```python
from Crypto.Util.Padding import unpad
from randcrack import RandCrack
from Crypto.Cipher import AES
from pwn import *
import os
import logging

logging.disable()

HOST = os.environ.get("HOST", "lazy-platform.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15004))


def getrandbytes(rc: RandCrack, n: int) -> bytes:
    if n % 4 != 0:
        return os.urandom(n)
    return b"".join(rc.predict_getrandbits(32).to_bytes(4, "little") for _ in range(n // 4))


if __name__ == "__main__":
    rc = RandCrack()

    conn = remote(HOST, PORT)

    for _ in range(624 // (32 // 4 + 16 // 4)):
        conn.sendlines([b"1", os.urandom(4).hex().encode()])

        conn.recvuntil(b"Key: ")
        key = bytes.fromhex(conn.recvline(False).decode())

        conn.recvuntil(b"IV: ")
        iv = bytes.fromhex(conn.recvline(False).decode())

        for i in range(0, len(key), 4):
            rc.submit(int.from_bytes(key[i:i+4], "little"))

        for i in range(0, len(iv), 4):
            rc.submit(int.from_bytes(iv[i:i+4], "little"))
    conn.sendline(b"3")

    conn.recvuntil(b"Ciphertext: ")
    ciphertext = bytes.fromhex(conn.recvline(False).decode())

    key = getrandbytes(rc, 32)
    iv = getrandbytes(rc, 16)

    print(unpad(
        AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext),
        AES.block_size
    ).decode())

```
