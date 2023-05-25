bits 64
L33T_CODE:

; code unpacker
; rdi contains license_ptr
; rsi contains lib_functions
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

; da chiave a registro
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

; copy address for mallocated memory to register
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

; copy flag from data to mallocated memory
cld
mov rdi, r9
add rsi, 24
mov rsi, [rsi]
mov rcx, r10
rep movsb
mov rax, 1
jmp L33T_CODE.repacker

; xor chars in mallocated memory with license
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

; call puts
mov rdi, r13
call [rsi+16]
mov rax, 1
jmp L33T_CODE.repacker

mov rax, 1 ; invalid instruction are treated as nop
jmp L33T_CODE.repacker
