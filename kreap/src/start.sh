#!/bin/bash
# Execute as root, drops privileges
# Needs files 31-kreap.rules, kreap.ko, chall, flag.txt, and start.sh in the same directory
# On the vm, we must wait > 5 minutes for the pacman keyring to initialize correctly (before installing nmap)

USERNAME=arch

useradd -m $USERNAME

# Init working directory
mkdir /app
mv kreap.ko chall flag.txt 31-kreap.rules /app
cd /app
chmod +x chall

# Add group
groupadd kreap
usermod $USERNAME -a -G kreap

# Setup udev rules
mkdir -p /etc/udev/rules.d
cp ./31-kreap.rules /etc/udev/rules.d

# Reload udev rules
udevadm control --reload-rules && udevadm trigger

# Insert module
insmod kreap.ko

# Drop sudo access
# rm /etc/sudoers.d/$USERNAME
# Change root password
# passwd xxx

# Install ncat
pacman -Sy --noconfirm nmap sudo

# Start challenge
sudo -u $USERNAME ncat -vc /app/chall -kl 0.0.0.0 1337