import hashlib
import string
import os

from pwn import *

context.arch = 'amd64'

HOST = os.environ.get("HOST", "pizza-orders.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15008))

p = remote(HOST, PORT)


def num_to_charseq(num, charset=string.ascii_letters):
    res = ""
    while True:
        if num < len(charset):
            res += charset[num]
            break
        res += charset[num % len(charset)]
        num //= len(charset)
    return res


def solve_pow(init_str, end_hash):
    num = 0
    while True:
        try_solve = init_str + num_to_charseq(num)
        if hashlib.sha256(try_solve.encode('ascii')).hexdigest().lower().endswith(end_hash.lower()):
            return try_solve
        num += 1


# Solve PoW (this can be activated or deactivated)
if p.recvuntil(b"Give me a string", timeout=0.5):
    proc = log.progress('PoW Required, solving...')
    p.recvuntil(b"starting in ")
    init_string = p.recvuntil(b" ")[:-1]
    p.recvuntil(b"ends in ")
    hash_end = p.recvuntil(b".")[:-1]
    p.sendline(solve_pow(init_string.decode(), hash_end.decode()).encode())
    proc.success('PoW Solved, Starting Exploit')
else:
    log.info("PoW not required, starting exploit")

# Write your exploit here
p.interactive()
