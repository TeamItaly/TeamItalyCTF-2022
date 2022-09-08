#!/bin/bash

setpriv --reuid=nobody --regid=nogroup --init-groups --inh-caps=-all \
  timeout ${TIMEOUT_POW:-60}s python3 /execute/pow.py
if [ $? -eq 0 ] 
then
  cd /home/ctf
  exec setpriv --reuid=ctf --regid=ctf --init-groups --inh-caps=-all \
    /usr/bin/timeout ${TIMEOUT_CHALL:-120}s /home/ctf/chall
fi
