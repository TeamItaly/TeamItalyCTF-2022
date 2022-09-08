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
