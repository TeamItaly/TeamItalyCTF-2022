global _start            ; Linker needs this symbol.

section .data           ; Data section

;; flag{01910023239281138890310208238219}

;; This declares a string of characters to write, and computes its length.             ; 
win_msg:    db      0x0a, 'Congratulations!', 0x0a, 'Sometimes you need a little wishful thinking to keep on hacking.',0xa      ; 
win_len:    equ     $ - win_msg         ; 
fail_msg:    db      0x0a, 'Oh no...', 0x0a, 'We better get ready for another impact.',0xa     ; 
fail_len:    equ     $ - fail_msg       ; 
format_msg:    db      0x0a, 'Not even the flag format...?',0xa     ; 
format_len: equ     $ - format_msg 
other_buf: db 	'fKfcmxnbfKfKnF$onF$omxnFnQnbnb$onSnQmxfK$onbfKnFfKnQnF$onQnFnbmx'
other_buf_len: equ     $ - other_buf 
flag_buf: db 'flag{}'

section .code           ; Code section
;;;;
;;;; vm.data - rsi  = 0x4089f0 - 0x4087a9 = 583

_start:
	jmp +7
	lol: db 0x48, 0xc7, 0xc3
	mov rsp, rsi
	add rsp, 581 + 24 ;; vm.data - rsi  = 0x4089f0 - 0x4087a9 = 583;; + 24 bytes
	add rsi, 323 ;; computed a posteriori using python
	mov r10, rsi
    xor rax, rax
    mov r9, rsi ;; LOADING flag_buf
    jmp CHECK_FLAG
    
_stampa:
    mov  rdi, 1
    mov  rax, 1   ; Syscall number (sys_write).
    syscall     ; Syscall instruction.  Enters kernel.
    ret

CARRY_ON:
    dec rsp
    mov rdx, r9 ; input = rcx AND other_buf = rdx	
	add rdx, win_len + fail_len + format_len ;; LOADING other_buf
	xor r15, r15
	inc r15
	xor rax, rax ;; Set counter to 0
	xor r8, r8
	inc r8
	xor rbx, rbx
	xor rdi, rdi
	LABEL_BYTE:
		xor rbp, rbp
		xor rbp, rax
		shl rbp, 63
		shr rbp, 63
		test rbp, rbp
		jz JUMP_OUT_LOAD ;; if rax is even (every two steps)
		CONTINUE_HERE:
		mov dil, BYTE [rdx+rax]	;; Load byte from ascii_art
		xor r11, r11
		inc r11
		inc r11
		xor r13, r13
	LABEL_BIT:
		ror r8b, 1 			;; Mask e.g., 0x0000010000000000
		mov r10, rbx		;; Storing in r10 the r8^th bit of rbx 
		and r10, r8
		neg r10				;; Trick to set r10 https://stackoverflow.com/questions/41174867/whats-the-easiest-way-to-determine-if-a-registers-value-is-equal-to-zero-or-no 
		sbb r10,r10 		
		inc r10
		not r10				;; Done
		rol r11b, 3 			;; Mask e.g., 0x0000010000000000
		mov r12, rdi		;; Storing in r12 the r11^th bit of rdi 
		and r12, r11
		neg r12				;; Trick to set r12 https://stackoverflow.com/questions/41174867/whats-the-easiest-way-to-determine-if-a-registers-value-is-equal-to-zero-or-no 
		sbb r12,r12 		
		inc r12
		not r12				;; Done
		xor r10, r12		;; r10=0 if r10==r12 and something else otherwise
		test r10, r10		
		setz R14B			;; set r14=1 if r10==r12
		and r15, r14		;; r15 gets set to 0 if r10!=r12 and stays 1 otherwise
		inc r13
		cmp r13, 4
		jl LABEL_BIT
	inc rax
	cmp rax, 0x40
	jl LABEL_BYTE

    mov  rsi, r9 ;; LOADING fail_msg
    add  rsi, win_len
    mov  rdx, fail_len
    mov  rdi, 1
	test r15, r15 			;; Decide to print success or fail
	jz END
    mov  rsi, r9 ;; LOADING win_msg
    mov  rdx, win_len
    xor  rdi, rdi
   	END:
   	call _stampa
    mov  rax, 0x3c   ; System call number (sys_exit)
    syscall     ; Syscall instruction.

    JUMP_OUT_LOAD:
    inc rsp
    mov bl, BYTE [rsp]
    jmp CONTINUE_HERE

    CHECK_FLAG:
    	xor rcx, rcx
    	xor rdx, rdx
    	mov cl, BYTE [r9 + rax + win_len+fail_len+format_len+other_buf_len]
    	mov dl, BYTE [rsp]
    	cmp dl, cl
    	jnz END_CHECK_FLAG
    	inc rax
    	inc rsp
    	cmp rax, 5
    	jl CHECK_FLAG
    	mov dl, BYTE [rsp+0x20]
    	cmp dl, BYTE [r9 + rax + win_len+fail_len+format_len+other_buf_len]
    	jz CARRY_ON
    END_CHECK_FLAG:
		mov  rsi, r9 ;; LOADING format_msg
		add rsi, win_len + fail_len
		mov  rdx, format_len
		jmp END