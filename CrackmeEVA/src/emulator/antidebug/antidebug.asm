global _start            ; Linker needs this symbol.

section .text           ; Code section
_start:
push rax
push rbx
push rcx
push rdx
push rsi
push rdi
push rbp
push r8
push r9
push r10
push r11
push r15
call next_instruction
next_instruction:
pop rsi
add rsi, 44 ;; addr of PTRACE_CHECK in rsi
mov edi, [rsi]
sub edi, 0x48ff3148 ;; first bytes of PTRACE_CHECK
cmp rdi, 0
je PTRACE_CHECK
xor rdi, rdi
mov r8, 312098
mov rdx, 0xd30a92546f566c8c
push 0x50505050 ;; TODO: change with DECRYPTION ROUTINE addr
ret
;; Antidebugging tools
PTRACE_CHECK:
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
xor r10, r10
mov rax, 0x65 ;; ptrace call
syscall
cmp rax, -1
je DETECTED
jmp SOFTBP_CHECK

SOFTBP_CHECK:
mov rsi, 0x50505050 ;; TODO: change with start HANDLER
xor rax, rax
xor rdi, rdi
LOOP_SOFTBP:
	mov dil, BYTE [rsi]
	sub dil, 0xcc
	neg rdi      ; ZF=1/0 for zero/non-zero, CF=not(ZF)
	sbb rdi,rdi  ; ebx = 0/-1 for CF=0/1
	inc rdi
	add rax, rdi 
	inc rsi
	cmp rsi, 0x50505050 ;; TODO: change with end HANDLER+1
jne LOOP_SOFTBP
cmp rax, 0 ;; checked manually with gdb after compilation
jne DETECTED
jmp CHECK_PROCESSES

CHECK_PROCESSES:
sub rsp, 20
mov r9, rsp
xor rbx, rbx
xor r10, r10 ;; set proc number to 0
CHECK_LOOP:
	inc r10 ;; inc proc number 
	mov rdx, 0x2f636f72702f ;; push "/proc/"
	mov [rsp], rdx 

	add rsp, 6

	mov rsi, 10
	mov rax, r10 	;; set the proc number
	ASCII_LOOP:
		xor rdx, rdx
		div rsi 		;; div stores the quotient in rax and reminder in rdx
		add dl, 0x30
		mov [rsp], dl 	;; place the ascii letter on the stack
		inc rsp 	  	;; go to next stack slot
		cmp rax, 0 	  	;; check if the digits are over
		jne ASCII_LOOP

	mov rdx, 0x7375746174732f ;; place "/status\x00"
	mov [rsp], rdx

	;; syscall open
	mov rdi, r9  ;; filename
	xor rsi, rsi ;; flags to 0
	xor rdx, rdx ;; mode to 0
	xor rax, rax
	add al, 2
	syscall
	mov r15, rax
	cmp rax, -1
	je CHECK_CONTINUE ;; unable to open the file
	;; syscall read
	mov rdi, rax ;; filedescriptor
	mov rsi, r9  ;; buffer
	mov rdx, 15  ;; count
	xor rax, rax
	syscall
	cmp rax, -1
	je CHECK_CLOSE ;; unable to read the file
	;; check if gdb 
	mov rsp, r9
	add rsp, 6
	mov rdx, [rsp] ;; load program name
	shl rdx, 32
	shr rdx, 32    ;; keep only the least important 32 bits
	sub rdx, 0xa626467 ;; check "gdb\n"
	neg rdx     	
	sbb rdx, rdx  	
	inc rdx			;; 1 only if proc name is "gdb\n"
	add rbx, rdx
CHECK_CLOSE:
	mov rdi, r15	;; get back the file descriptor
	mov rax, 0x3
	syscall			;; close the file
CHECK_CONTINUE:
	mov rsp, r9 	;; reset rsp
	cmp r10, 99999  ;; check proc number
	jl CHECK_LOOP
add rsp, 20 ;; restore stack
cmp rbx, 0  ;; check if gdb present
jne DETECTED
jmp END

DETECTED:
mov rsi, 0x50505050 ;; TODO: change with vm_flag addr
xor rdx, rdx		;; setting vm.reg.flag=1;
inc dl
mov [rsi], dl
mov rsi, 0x50505050 ;; TODO: change with backdoor addr
mov rdi, 0x13fac560f5be149 ;; destroy backdoor
mov [rsi + 0], rdi
mov rdi, 0x6143e8659e83b4c3
mov [rsi + 8], rdi
mov rdi, 0xf7958ced456826c1
mov [rsi + 16], rdi
mov rdi, 0x8211922b7d8ca057
mov [rsi + 24], rdi
mov rdi, 0x6abaab24a962d4a9
mov [rsi + 32], rdi
mov rdi, 0xb1714fa11a78ff01
mov [rsi + 40], rdi
mov rdi, 0x3af3fed53aaabb54
mov [rsi + 48], rdi
mov rdi, 0x17df10fc1dcb3453
mov [rsi + 56], rdi
mov rdi, 0x105d89c1e587aad7
mov [rsi + 64], rdi
mov rdi, 0x46bab45d756f4410
mov [rsi + 72], rdi
mov rdi, 0xa28056fc4f6ac4b
mov [rsi + 80], rdi
jmp END_NO_MPROTECT
END:
mov rdi, [0x50505050] ;; TODO: change with vm_addr
mov r15, 0xfffffffffffff000
and rdi, r15
mov rsi, 0x5000 
mov rdx, 7 					
mov rax, 0xa
END_NO_MPROTECT:
syscall  			  ;; calling mprotect on the heap for 5 pages
pop r15
pop r11
pop r10
pop r9
pop r8
pop rbp
pop rdi
pop rsi
pop rdx
pop rcx
pop rbx
pop rax
push 0x50505050 ;; TODO: change with HANDLER+910
ret