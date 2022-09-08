# TeamItaly CTF 2022

## Speaking with hands (7 solves)

The flag is saved in the executable, and it's xored with the license. The program iterates for every character of the license and it executes different instructions, according to the character. Here is a map of the actions:

- `x`: `mov` the first char from `LICENSE` into `r9`
- `y`: `mov` the first char from `LICENSE` into `r10`
- `!`: `mov` the first char from `LICENSE` into `r11`
- `a`: `mov` the first char from `LICENSE` into `r12`
- `1`: `mov` the first char from `LICENSE` into `r13`
- `r`: `mov` `playground` into `r9`
- `O`: `mov` `playground` into `r10`
- `l`: `mov` `playground` into `r11`
- `2`: `mov` `playground` into `r12`
- `W`: `mov` `playground` into `r13`
- `S`: copy from `flag` to `*r9`, `r10` bytes
- `b`: xor `*r10` with license, `r11` bytes
- `?`: call `malloc`, with `r9` bytes. The allocated memory will be called `playground`
- `j`: call `free` address `r11`
- `h`: call `print_flag` address `r13`

Some instructions can use the next character of the license as an argument. If the license is correct, then the binary will print the flag.
The executable also checks that the inserted license is 15 characters long.
The instructions that are called when checking the license are obfuscated. To execute an action the relevant code gets deobfucated, executed and then obfucated again.

### Solution

The relevant instructions, along with the obfuscator, are placed in a separated memory area.
The code gets deobfuscated according to this formula:
`clear_byte = obfuscated_byte ^ (0x13371337 + offset)`
where offset is the position of the byte relative to the beginning of the memory area.

The deobfuscated assembly code looks like this:

```assembly
L33T_CODE:

; code unpacker
; rsi contains license_ptr
; rdi contains lib_functions
; rdx contains "function" offset
; rcx contains "function" size
push rbp
mov rbp,rsp
push r8
push rdx
push rcx
push rsi
mov rsi, 0 ; flag, jump to code
.encoder:
mov rax, [rbp-16] ; init key
mov rcx, 3
mul rcx
add rax, 0x13371337

mov rcx, [rbp-8] ; move pointer to function
add rcx, [rbp-16]
mov rbx, [rbp-24]
add rbx, rcx ; last address
.loop:
xor [rcx], al ; decode / encode
inc rcx ; increment pointer
add rax, 3 ; update key
cmp rcx, rbx
jl L33T_CODE.loop
cmp rsi, 0
jne L33T_CODE.finish
pop rsi
mov rax, r8
add rax, [rbp-16]
jmp rax

; code repacker
.repacker:
push rax ; save chars to skip
mov rsi, 1 ; flag, jump to finish
jmp L33T_CODE.encoder
.finish:
pop rax
leave
ret

; from license to register
xor r9, r9
mov r9b, byte [rdi + 1]
mov rax, 2
jmp L33T_CODE.repacker

;
xor r10, r10
mov r10b, byte [rdi + 1]
mov rax, 2
jmp L33T_CODE.repacker

;
xor r11, r11
mov r11b, byte [rdi + 1]
mov rax, 2
jmp L33T_CODE.repacker

;
xor r12, r12
mov r12b, byte [rdi + 1]
mov rax, 2
jmp L33T_CODE.repacker

;
xor r13, r13
mov r13b, byte [rdi + 1]
mov rax, 2
jmp L33T_CODE.repacker

; copy address for allocated memory to register
mov r9, r15
mov rax, 1
jmp L33T_CODE.repacker

;
mov r10, r15
mov rax, 1
jmp L33T_CODE.repacker

;
mov r11, r15
mov rax, 1
jmp L33T_CODE.repacker

;
mov r12, r15
mov rax, 1
jmp L33T_CODE.repacker

;
mov r13, r15
mov rax, 1
jmp L33T_CODE.repacker

; copy flag from data to allocated memory
cld
mov rdi, r9
add rsi, 24
mov rsi, [rsi]
mov rcx, r10
rep movsb
mov rax, 1
jmp L33T_CODE.repacker

; xor chars in allocated memory with license
xor rax, rax
mov rcx, r10 ; move pointer to memory playground
mov rbx, rcx ; last address
add rbx, r11 ; set here flag length

add rsi, 32
mov rsi, [rsi]
.xor_loop:
lodsb
xor byte [rcx], al ; decode
inc rcx ; increment pointer
cmp rcx, rbx
jl L33T_CODE.xor_loop
mov rax, 1
jmp L33T_CODE.repacker

; call malloc
mov rdi, r9
call [rsi]
mov r15, rax
mov rax, 1
jmp L33T_CODE.repacker

; call free
mov rdi, r11
call [rsi+8]
mov rax, 1
jmp L33T_CODE.repacker

; call print_flag
mov rdi, r13
call [rsi+16]
mov rax, 1
jmp L33T_CODE.repacker

mov rax, 1 ; invalid instruction are treated as nop
jmp L33T_CODE.repacker
```

The license should be built this way:

- `x\x0f`: Set `r9` with the flag length
- `?`: call `malloc` to allocate the memory `playground`
- `r`: set `r9` with the address of `playground`
- `y\x0f`: set `r10` with the flag length
- `S`: copy the flag to the memory pointed by `playground`
- `O`: set `r10` with the address of `playground`
- `!\x0f`: set `r11` with the flag length
- `b`: xor the flag with the license
- `W`: set `r13` with the address of `playground`
- `h`: call `print_flag` (that's basically a `printf`)
- `l`: set `r11` with the address of `playground`
- `j`: call `free`

The correct license is `x\x0f?ry\x0fSO!\x0fbWhlj`
