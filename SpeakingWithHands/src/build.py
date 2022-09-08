import binascii
import os
from pwn import *

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


os.system("yasm -m amd64 -o src/tmp.bin src/code.asm")

dec_offset = 0x5e
key = 0x13371337 + (dec_offset*3)

with open("src/tmp.bin", 'rb') as f:
    binary_code = f.read()

packed_code = bytearray()
for i in range(dec_offset,len(binary_code)):
    encr = binary_code[i] ^ (key % 256)
    packed_code += encr.to_bytes(1,"little")
    
    key += 3

hex_code = binascii.hexlify(binary_code[0:dec_offset] + packed_code).decode()
hex_code_0 = ""

for x in range(0,len(hex_code),2):
    hex_code_0 += f"\\x{int(hex_code[x:x+2],16):02x}"

with open("src/bin.h", 'w') as f:
    f.write('#define BIN_CODE "' + hex_code_0 + '"')

f.close()

os.system("gcc -s src/main.c -o src/challenge")