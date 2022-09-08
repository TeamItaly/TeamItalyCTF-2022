# TeamItaly CTF 2022

## Alice's Adventures in Goland (2 solves)

The challenge was written in **Go**, statically compiled, stripped and without debug information.
The binary presents questions, which the correct combination of answers will print the flag (multiple solution exists)

### Solution

The challenge to determine the right combination of answers used a three-dimensional **_8x8x8_** maze, and depending on the answer the user gave the player moved within this maze **_(6 answers each for every axes and direction)_**. To win the user had to reach coordinate **_(7,7,7)_** beginning at **_(0,0,0)_**. The maze data is on the stack, at first it may seem high entropy random data but the program basically uses the parity of each byte to determine where a user can move (if the byte is odd it is a valid position, otherwise it is not and the program exits).

The binary as already said is statically compiled, stripped, and without any debug information, so function names are not present, but since there still is the `.gopclntab` (The version of Go I used is recent [>= 1.2](https://docs.google.com/document/d/1lyPIbmsYbXnpNj57a261hgOYVpNRcgydurVQIyZOz_o/pub)) section it is possible to recover function names, and this makes the decompiled much more readable. Multiple already written scripts exists for _Ghidra_, _IDA_, and _Binary Ninja_. There is a few that i personally tested.

> - https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/go_func.py (Ghidra)
> - https://github.com/mandiant/GoReSym (IDA)

To improve more the decompiled, you can use script to identify strings within functions since a string in Go is not simply [NULL-terminated](https://cujo.com/wp-content/uploads/2020/09/Picture19.png.webp). Recent version of _IDA_ since version 7.4 do this automatically, but _Ghidra_ needs scripts, here are a few.

> - https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_dynamic_strings.py
> - https://github.com/getCUJO/ThreatIntel/blob/master/Scripts/Ghidra/find_static_strings.py

In the binary there exist anti-debug mechanismd, and a timeout. These are implemented with _goroutines_ and may be annoying, but they are easily patchable by replacing the calls to **_runtime.newproc_** with _NOP_

### Exploit

```python
#!/bin/env python3
from pwn import remote, log
import re
import os

# Host and port
HOST = os.environ.get("HOST", "alice-in-goland.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15006))

# Retrieve flag from remote service
flag_re_syn = "(flag{[A-Za-z0-9!_?]+})"
flag_regex = re.compile(flag_re_syn)

# Solution to the maze
path = "aaaccececeddeaceccebccaadaace"

with remote(HOST, PORT) as r:
    p = log.progress("retrieving flag")

    for move in path:
        r.clean()
        r.sendline(move.encode())

    msg = r.recvallS()

    flag = flag_regex.findall(msg)

    if flag:
        p.success("success!")
        log.info(flag[0])
    else:
        p.failure("the service might not work properly")

```
