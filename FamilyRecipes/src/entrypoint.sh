#!/bin/bash

echo "[+] Waiting for connections"
socat -T 30 tcp-l:1337,reuseaddr,fork EXEC:"/opt/run.py",pty,stderr
echo "[+] Exiting"
