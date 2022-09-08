gcc -g -no-pie -fno-stack-protector emulatore.c -o emulator
python3 assemble_trap.py
strip -s emulator
