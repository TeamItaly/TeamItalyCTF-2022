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

def convert_passwords(passwords, salt: str):
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

def create_ciphertext(key_list):
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

    zL_kannan = block_matrix([[zL.LLL(), zero_matrix(l+d, 1)], [target.row(), M]])
    zL_kannan = zL_kannan.LLL()

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

    r.recvuntil('troubles: ')
    print(r.recvline())
    # r.interactive()

if __name__ == "__main__":
    main()
