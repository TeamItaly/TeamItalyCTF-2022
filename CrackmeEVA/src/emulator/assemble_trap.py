from pwn import *
import random
import math

def random_pad(string, length):
    num = length - len(string)
    pad = b''
    if num>0:
        pad = b''.join(bytes([random.randint(0,255)]) for _ in range(num))
    return string+pad

def encrypt_payload(payload, key):
    result = b""
    for i in range(len(payload)//8):
        chunk = payload[i*8:i*8+8]
        result += p64(u64(chunk)^key)
    return result

emulator = ELF("./emulator")

vm_addr = emulator.symbols['vm']
handler = emulator.symbols['handler']
_start = emulator.symbols['_start']
evildata_ptr = emulator.symbols['evildata']
evildata = u64(emulator.read(evildata_ptr, 8))
start_stub_label = emulator.symbols['start_stub']

# seen from gdb
vm_data = vm_addr + 0x10
vm_ro_data = vm_addr + 0x8
vm_flag = vm_addr + 45
handler_lea = handler + 893 # addr of lea in div 0
handler_jmp = handler + 910 # addr of jmp in div 0
handler_end = handler + 1853 # end of the function

# choosen at random
start_stub_offset = 43
antidebug_offset = 1338
decryption_offset1 = 2037
backdoor_offset = 3121
decryption_offset2 = 3713
evildata_len = 4000
start_stub_len = 200 # if you change it you have to fix the __asm__ in emulatore.c to have more/less nops

antidebug_addr = evildata + antidebug_offset
backdoor_addr = evildata + backdoor_offset
decryption_addr1 = evildata + decryption_offset1
decryption_addr2 = evildata + decryption_offset2
start_stub_addr = start_stub_label + start_stub_offset
# choosen at random
key = 0xd30a92546f566c8c

ik1vm_logo = b"\n\n\n\n\t\t.___  __     ____          _____    \n\t\t|   ||  | __/_   |___  __ /     \\   \n\t\t|   ||  |/ / |   |\\  \\/ //  \\ /  \\  \n\t\t|   ||    <  |   | \\   //    Y    \\ \n\t\t|___||__|_ \\ |___|  \\_/ \\____|__  / \n\t\t          \\/                    \\/  \n                                    \n\n\n\n\x00"

#system("./asmcompile.sh")
#antidebug_program = ELF('./antidebugf')
#antidebug = antidebug_program.get_section_by_name('.text').data()
#print(''.join(["\\x" + hex(e)[2:].rjust(2, '0') for e in antidebug])) # search for \x50\x50\x50\x50
## Go read antidebug.asm
antidebug = b"\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41\x53\x41\x57\xe8\x00\x00\x00\x00\x5e\x48\x83\xc6\x2c\x8b\x3e\x81\xef\x48\x31\xff\x48\x48\x83\xff\x00\x74\x19\x48\x31\xff\x41\xb8" + p32(528) + b"\x48\xba\x8c\x6c\x56\x6f\x54\x92\x0a\xd3\x68" + p32(decryption_addr1) + b"\xc3\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xd2\xb8\x65\x00\x00\x00\x0f\x05\x48\x83\xf8\xff\x0f\x84\x03\x01\x00\x00\xeb\x00\xbe" + p32(handler) + b"\x48\x31\xc0\x48\x31\xff\x40\x8a\x3e\x40\x80\xef\xcc\x48\xf7\xdf\x48\x19\xff\x48\xff\xc7\x48\x01\xf8\x48\xff\xc6\x48\x81\xfe" + p32(handler_end + 1) + b"\x75\xe1\x48\x83\xf8\x00\x0f\x85\xcd\x00\x00\x00\xeb\x00\x48\x83\xec\x14\x49\x89\xe1\x48\x31\xdb\x4d\x31\xd2\x49\xff\xc2\x48\xba\x2f\x70\x72\x6f\x63\x2f\x00\x00\x48\x89\x14\x24\x48\x83\xc4\x06\xbe\x0a\x00\x00\x00\x4c\x89\xd0\x48\x31\xd2\x48\xf7\xf6\x80\xc2\x30\x88\x14\x24\x48\xff\xc4\x48\x83\xf8\x00\x75\xeb\x48\xba\x2f\x73\x74\x61\x74\x75\x73\x00\x48\x89\x14\x24\x4c\x89\xcf\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x04\x02\x0f\x05\x49\x89\xc7\x48\x83\xf8\xff\x74\x46\x48\x89\xc7\x4c\x89\xce\xba\x0f\x00\x00\x00\x48\x31\xc0\x0f\x05\x48\x83\xf8\xff\x74\x26\x4c\x89\xcc\x48\x83\xc4\x06\x48\x8b\x14\x24\x48\xc1\xe2\x20\x48\xc1\xea\x20\x48\x81\xea\x67\x64\x62\x0a\x48\xf7\xda\x48\x19\xd2\x48\xff\xc2\x48\x01\xd3\x4c\x89\xff\xb8\x03\x00\x00\x00\x0f\x05\x4c\x89\xcc\x49\x81\xfa\x9f\x86\x01\x00\x0f\x8c\x51\xff\xff\xff\x48\x83\xc4\x14\x48\x83\xfb\x00\x75\x05\xe9\xaf\x00\x00\x00\xbe" + p32(vm_flag) + b"\x48\x31\xd2\xfe\xc2\x88\x16\xbe" + p32(backdoor_addr) + b"\x48\xbf\x49\xe1\x5b\x0f\x56\xac\x3f\x01\x48\x89\x3e\x48\xbf\xc3\xb4\x83\x9e\x65\xe8\x43\x61\x48\x89\x7e\x08\x48\xbf\xc1\x26\x68\x45\xed\x8c\x95\xf7\x48\x89\x7e\x10\x48\xbf\x57\xa0\x8c\x7d\x2b\x92\x11\x82\x48\x89\x7e\x18\x48\xbf\xa9\xd4\x62\xa9\x24\xab\xba\x6a\x48\x89\x7e\x20\x48\xbf\x01\xff\x78\x1a\xa1\x4f\x71\xb1\x48\x89\x7e\x28\x48\xbf\x54\xbb\xaa\x3a\xd5\xfe\xf3\x3a\x48\x89\x7e\x30\x48\xbf\x53\x34\xcb\x1d\xfc\x10\xdf\x17\x48\x89\x7e\x38\x48\xbf\xd7\xaa\x87\xe5\xc1\x89\x5d\x10\x48\x89\x7e\x40\x48\xbf\x10\x44\x6f\x75\x5d\xb4\xba\x46\x48\x89\x7e\x48\x48\xbf\x4b\xac\xf6\xc4\x6f\x05\x28\x0a\x48\x89\x7e\x50" + b"\xe9\x29\x00\x00\x00" + b"\x48\x8B\x3C\x25" + p32(vm_addr) + b"\x49\xC7\xC7\x00\xF0\xFF\xFF\x4C\x21\xFF\x48\xC7\xC6\x00\x50\x00\x00\x48\xC7\xC2\x07\x00\x00\x00\x48\xC7\xC0\x0A\x00\x00\x00\x0F\x05" + b"\x41\x5f\x41\x5b\x41\x5a\x41\x59\x41\x58\x5d\x5f\x5e\x5a\x59\x5b\x58\x68" + p32(handler_jmp) + b"\xc3"

juicy_code = antidebug[66:]
juicy_code = juicy_code.ljust(len(juicy_code) + abs(8-len(juicy_code)%8),b"\x90") # pad to 8 bytes
print(f"antidebug_len: {len(juicy_code)}")
assert(len(juicy_code) == 528) # fix antidebug otherwise
antidebug = antidebug[:66] + encrypt_payload(juicy_code, key)

# store registers
# push rdi
# push rsi
# push rdx
# push rax
start_stub_savereg = b"\x57\x56\x52\x50"
# mprotect setup for rwx on .text, .bss, .data ...
# mov rdi, 0x400000
# mov rsi, 0x6000
# mov rdx, 7
# mov rax, 0xa
# syscall
start_stub_mprotect = b"\x48\xC7\xC7\x00\x00\x40\x00\x48\xC7\xC6\x00\x60\x00\x00\x48\xC7\xC2\x07\x00\x00\x00\x48\xC7\xC0\x0A\x00\x00\x00\x0F\x05"

# Patch code
# 0:  68 99 59 40 00          push   antidebug_addr
# 5:  c3                      ret
# ....                        nop
# 17: e9 92 03 00 00          jmp 0x401b44
patch = (b"\x68" + p32(antidebug_addr) + b"\xC3").ljust(17, b'\x90') + b"\xe9\x92\x03\x00\x00\x48\x8b"
#patch += b'\x90'*(17-len(patch)) + b"\xe9\x92\x03\x00\x00\x48\x8b"
patch_values = [patch[8*i:8*i+8] for i in range(len(patch)//8)]

assert(math.isclose(len(patch)/8, 3))
# Patching code
# mov rsi, handler+893
# mov rdi, 0x9090c30040599968
# mov [rsi], rdi
# mov rdi, 0x909090c300405999
# mov [rsi+8], rdi
# mov rdi, 0x90909090c3004059
# mov [rsi+16], rdi
start_stub_patch = b"\x48\xC7\xC6" + p32(handler_lea) + b"\x48\xBF" + patch_values[0] + b"\x48\x89\x3E\x48\xBF" + patch_values[1] + b"\x48\x89\x7E\x08\x48\xBF" + patch_values[2] + b"\x48\x89\x7E\x10"
# Redo start function ops
# pop rax
# pop rdx
# pop rsi
# pop rdi
# XOR        EBP,EBP
# MOV        R9,RDX
# POP        RSI
# push       _start + 10
# ret
start_stub_end = b"\x58\x5A\x5E\x5F" + b'\x31\xed\x49\x89\xd1\x5e' + b"\x68" + p32(_start+10) + b"\xC3"
start_stub = start_stub_savereg + start_stub_mprotect + start_stub_patch + start_stub_end
start_stub_padded = random_pad(b'', start_stub_offset) + start_stub
assert(len(start_stub_padded) <= start_stub_len)
start_stub_padded = random_pad(start_stub_padded, start_stub_len)

print(f"len start_stub: {len(start_stub)}")

# Backdoor code:
# mov rsi, [vm.data]     ;; load vm.data in rsi
# mov rdi, [rsi]          ;; offset is the first field (8 bytes) of data
# mov r8, [rsi+8]         ;; len is the second field
# mov rdx, [rsi+16]       ;; key is the third field
# mov rsi, [vm.ro_data]     ;; load vm.ro_data in rsi
# push DECRYPTION_ROUTINE
# ret
backdor_code = b"\x48\x8B\x34\x25" + p32(vm_data) + b"\x48\x8B\x3E\x4C\x8B\x46\x08\x48\x8B\x56\x10\x48\x8B\x34\x25" + p32(vm_ro_data) + b"\x68" + p32(decryption_addr2) + b"\xC3"


# DECRYPTION_ROUTINE:
#     xor rax, rax   ;; zero counter
#     add rsi, rdi   ;; addr + offset
# DECRYPTION_LOOP:
#     cmp rax, r8    ;; if (counter < len) decrypt
#     jge END_DECRYPTION
#     mov rbx, [rsi+rax]
#     xor rbx, rdx
#     mov [rsi+rax], rbx
#     add rax, 8     ;; increment counter
#     jmp DECRYPTION_LOOP
# END_DECRYPTION:
# jmp rsi                 ;; jump at addr + offset
decryption_routine = b"\x48\x31\xC0\x48\x01\xFE\x4C\x39\xC0\x7D\x11\x48\x8B\x1C\x06\x48\x31\xD3\x48\x89\x1C\x06\x48\x83\xC0\x08\xEB\xEA\xFF\xE6"

newdata = random_pad(ik1vm_logo, antidebug_offset)
newdata += antidebug
newdata = random_pad(newdata, decryption_offset1)
newdata += decryption_routine
newdata = random_pad(newdata, backdoor_offset)
newdata += backdor_code
newdata = random_pad(newdata, decryption_offset2)
newdata += decryption_routine
newdata = random_pad(newdata, evildata_len)

# patch the data section
emulator.write(evildata, newdata)

# patch the _start routine
patch_start = b"\x68" + p32(start_stub_addr) + b"\xC3"
emulator.write(_start+4, patch_start) # skip endbr64 and patch

emulator.write(start_stub_label, start_stub_padded) # write start stub in .text

emulator.save()

print(f"ik1vm_logo: {hex(evildata)}")
print(f"start_stub: {hex(start_stub_addr)}")
print(f"antidebug: {hex(antidebug_addr)}")


#system("strip -s emulator")

