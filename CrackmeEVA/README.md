# TeamItaly CTF 2022

## Ik1VM - CrackmeEVA (1 solves)

This challenge consists of an emulator and a program to be emulated. The goal of the challenge is to find the activation code that satisfies the emulated program. The two programs (ik1vm and crackme_eva) cooperate and make the reverser life hard via antidebugging tricks, self-modifying code and exploitation of buffer overflows.

The flow of the challenge can be better understood by looking at the commented source codes.

### Solution

There are several ways to solve the challenge. Most of the tricks in the challs require the rev.eng. to understand what is going on.

The emulator starts and patches its own handler of the division by 0, by making it call an antidebugging routine.
crackme_eva loads the flag in memory, sets up the data tape and performs a division by 0.
The antidebugging routine gets triggered. If it's the first time that it gets called, it unpacks and then executes (otherwise it skips the unpacking routine).
It checks:

1. if ptrace has already been called on the emulator
2. if there is a breakpoint in the handler code (by counting the 0xcc in memory)
3. if there's a process called gdb (by enumerating /proc/.../status)
   If any of these conditions is met, the antidebugging sets the vm.reg.flag to 1 and destroys the "backdoor" by overwriting it with rubbish. The control gets back to crackme_eva.

crackme_eva checks the flag. If the flag is 1, it will never tell that the flag is ok. It will just output that the format is wrong (with an actual check) or that the flag is incorrect.

If the flag is 0, crackme_eva starts using the 'call' instruction of the emulator, till the stack is overflown. Then, some invalid opcode is read, the emulator returns on a small x86-64 shellcode at the end of the crackme_eva code. This snippet calls a function hidden in the emulator data section (the "backdoor"). This function decrypts the ro_data tape of crackme_eva (which contains x86-64 bytecode) and jumps to it.

Here's where the real check and challenge is.
The flag is hidden in some bits of a string in ro_data and the assembly performs checks between the flag in the data section and the one in the bits of this string.

Here I see four main possibilities:

1. keep on reversing and writing some automated debugging tool that dumps the bits to reconstruct the flag.
2. keep on reversing and writing the inverse function (w.r.t. to the flag check)
3. extract the x86-64 code, create a binary with it and run angr on it
4. setup angr to handle self-modifying code etc.
