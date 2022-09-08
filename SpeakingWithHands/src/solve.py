#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge")

context.binary = exe
context.arch = 'amd64'
context.terminal = ["tilix", "-e"]

gdb_script = """
b * main + 311
c
"""

if __name__ == "__main__":
    r = process([exe.path])
    r.sendline(b"x\x0f?ry\x0fSO!\x0fbWhlj")
    r.interactive()
