#!/bin/bash
mkdir vm
guestmount -a Arch-Linux-x86_64-basic-20220902.79941.qcow2 -m /dev/sda2 vm
cp chall kreap.ko ../flag.txt ../src/31-kreap.rules ../src/start.sh vm/home/arch/
umount vm
rmdir vm
# qemu-system-x86_64 Arch-Linux-x86_64-basic-* -m 4096 -smp 2 -nic user,hostfwd=tcp::1337-:1337