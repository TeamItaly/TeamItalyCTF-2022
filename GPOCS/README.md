# TeamItaly CTF 2022

## GPOCS (8 solves)

GPOCS is a service that generates password and allows you to test them by asking you to find which password it has generated. By rate-limiting the amount of attempts you can do, it prevents you from simply brute-forcing the passwords: you are only given 8 testing attempts over a password range of $12^2 = 144$ passwords. Since this is repeated 20 times, the probability of solving the challenge by pure luck is extremely low.

### Solution

The player is given a decryption oracle that checks if the password can correctly decrypt an attacker-provided ciphertext. This allows for a key partitioning oracle [1] where instead of trying 144 keys singularly, each query can be used to test for multiple keys at the same time, allowing for a binary search of the correct key. Since $\lceil\log(2, 144)\rceil = 8$, the number of queries is exactly sufficient to get the correct key everytime. This is done by creating a ciphertext that decrypts correctly under multiples keys (a "splitting ciphertext").

This attack can be executed against any non key-committing AEAD, such as AES-GCM and ChaCha20-Poly1305 (the latter being the one used in this challenge). Unfortunately, while the algebraic structure of AES-GCM allows for an easy creation of splitting ciphertexts, with ChaCha20-Poly1305 we have a harder time in running the exploit. This is because in ChaCha20-Poly1305 there are a few design choices that make it harder to compute an attack. For example, the cipehrtext is split into blocks of 16 bytes and a 0x01 is appended, forcing each block to be in the $[2^{128}, 2^{129}-1]$ range. In fact, the paper by Len et al. only manages to create splitting ciphertexts that decrypt under 10 keys at most. This, of course, makes it impossible to run a binary search, since the first search requires to check 128 keys in a single run.

Luckily, there are lattice methods that allow us to compute ChaCha20-Poly1305 splitting ciphertexts, such as the ones described by Kryptos Logic [2]. They provide part of the code, which is incomplete and cannot be used to compute large-scale splitting ciphertexts since it tries to compute an exact closest vector. The code must then be modified using Kannan embedding and BKZ to actually manage to solve the challenge by computing an approximation.

Another possible option is to keep using the original code by Len et al. (https://github.com/julialen/key_multicollision) and use an inequality solver e.g. (https://github.com/rkm0959/Inequality_Solving_with_CVP) to compute a solution that matches the constraint (I have not tested this alternative yet).

### Flag

```
flag{c4n_1_us3_fd1sk_t0_p4rt1t10n_my_k3ys?}
```

### Exploit

```python
import itertools
import base64
import math
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pwn import *

HOST = os.environ.get("HOST", "gpocs.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15005))

context.log_level = 'debug'

q = 2^130-5
R = GF(q)
P.<x> = R[]

def convert_passwords(passwords: list[str], salt: str):
    result = []
    salt = bytes.fromhex(salt)

    for password in passwords:
        k = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())
        chacha = Cipher(ChaCha20(k, b'\x00' * 16), mode=None).encryptor()
        rs = chacha.update(b'\x00'*32)
        r = int.from_bytes(rs[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
        s = int.from_bytes(rs[16:], 'little')
        result.append((k, r, s))
    return result

def create_ciphertext(key_list: list[tuple[bytes, bytes, bytes]]):
    k, r, s = zip(*key_list)

    l = len(k)
    d = 30

    # target common tag
    tag = randint(0, 2^128)

    # final polynomial has l+d blocks
    E = ((16 * (l+d)) << 64) + 2^128
    t = [ (((tag - s[i]) % 2^128) - E*r[i])/r[i]^2 % q for i in range(l) ]

    print("[+] Starting interpolation")

    # Interpolate
    m = P.lagrange_polynomial(zip(r, t))

    print("[+] Finished interpolation, building lattice")

    # CRT
    p = prod([ x - ri for ri in r ])
    f = x^d + P.random_element(d-1)

    assert(gcd(f, p) == 1)

    ma = m * f * inverse_mod(f, p) % (p*f)
    mb =     p * inverse_mod(p, f) % (p*f)

    # build q-ary lattice
    qL = matrix(R, [ list(x^i * mb % (p*f)) for i in range(d) ])
    zL = block_matrix(ZZ, 2, 1, [
      qL.echelon_form().change_ring(ZZ),
      block_matrix(ZZ, 1, 2, [zero_matrix(l, d), identity_matrix(ZZ, l) * q])
    ])
    target = vector([ ZZ((2^128+2^127) - ma[i]) for i in range(l+d) ])

    print("[+] Running CVP (This is a slow process)")

    # Build kannan embedding

    M = 2**114 # magic numbers!

    zL_kannan = block_matrix([[zL.BKZ(), zero_matrix(l+d, 1)], [target.row(), M]])
    zL_kannan = zL_kannan.BKZ()

    for row in zL_kannan:
        if row[-1] == M:
            v = target - row[:-1]
            break
    else:
        raise Exception("Correct row not found")

    # # Alternative solution with exact CVP solver, doesn't work for our sizes!
    # L = IntegerMatrix.from_matrix(zL.LLL())
    # v1 = CVP.closest_vector(L, target)
    # print(v1)

    print("[!] Done, running assertions")

    final = vector(ZZ, (vector(v)+vector(ma))%q)
    assert( (final - vector([2^128+2^127]*(l+d))).norm() <= sqrt(l+d)*2^127 )
    assert( all([ 2^128 <= block < 2^129 for block in final ]) )
    finalp = sum([ x^i * final[i] for i in range(l+d)])
    assert( all([ finalp(ri) == ti for ri, ti in zip(r, t) ]) )
    assert( all([ (ZZ((finalp * x^2 + E*x)(ri)) + si) % 2^128 == tag for ri,si in zip(r,s)]) )
    ciphertext = b''.join([ int(block % 2^128).to_bytes(16, 'little') for block in reversed(final) ]) + tag.to_bytes(16, 'little')
    for ki in k:
        aead = ChaCha20Poly1305(ki)
        aead.decrypt(b'\x00'*12, ciphertext, None)

    return base64.b64encode(b'\x00' * 12 + ciphertext)

def submit_ciphertext(r, ctxt):
    r.sendline(b'1')

    # The timeout here is in theory useless, but pnwtools fucks up somehow
    # and if no timeout is given it will get stuck
    r.recvuntil(b'ciphertext (base64-encoded):', timeout=2)

    r.sendline(ctxt)
    res = r.recvline()
    r.recvuntil(b'>')
    return b'OK' in res


def handle_round(r):
    r.recvuntil(b'following words: \n')
    words = r.recvline().decode().strip().split()
    r.recvuntil(b'salt (hex-encoded): ')
    salt = r.recvline().decode().strip()
    r.recvuntil(b'>')
    print('[!] Using words: ', words)
    print('[!] Using salt: ', salt)

    assert len(words) == 12

    passwords = ['-'.join(ww) for ww in itertools.product(words, repeat=2)]

    # Run binary search, until one candidate is left
    while (l := len(passwords)) > 1:
        print(f'[!] Running binary search, current search space length: {l}')
        half_idx = math.ceil(l/2)
        half = passwords[:half_idx]
        ctxt = create_ciphertext(convert_passwords(half, salt))

        if submit_ciphertext(r, ctxt):
            passwords = half
        else:
            passwords = passwords[half_idx:]

    print(f'[*] Found password! {passwords[0]}')

    r.sendline(b'2')
    r.recvuntil('Send your password guess: ')
    r.sendline(passwords[0].encode())
    r.recvuntil(b'Good job!')

def main():
    r = remote(HOST, PORT)
    r.sendline(b'')

    for i in range(20):
        print(f'\n!!! ------ CURRENTLY IN ROUND {i+1} ------- !!!\n')
        handle_round(r)

    r.interactive()

if __name__ == "__main__":
    main()
```

[1] Len et al. "Partitioning Oracle Attacks" (USENIX Security 2021)
[2] Kryptos Logic "Faster Poly1305 Key Multicollisions" (https://www.kryptoslogic.com/blog/2021/01/faster-poly1305-key-multicollisions/)
