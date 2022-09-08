from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import random
import signal
import os

TIMEOUT = 300
FLAG = os.environ.get("FLAG", "flag{test}").encode()


def getrandbytes(n: int) -> bytes:
    return random.getrandbits(n * 8).to_bytes(n, "little")


def handle():
    print("Welcome to Lazy platform! If you want to decrypt some messages, you can't do that here, you'll have to do it on your own")

    while True:
        print("Choose one of the following options")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[3] Get encrypted flag")
        print("[4] Exit")
        option = input("> ")

        if option == "1":
            message = input("Enter a message to encrypt: ")
            key = getrandbytes(32)
            iv = getrandbytes(16)
            ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
                pad(message.encode(), AES.block_size))
            print("Ciphertext:", ciphertext.hex())
            print("Key:", key.hex())
            print("IV:", iv.hex())
        elif option == "2":
            print("I can't do that at the moment, I'm cooking a pizza")
        elif option == "3":
            key = getrandbytes(32)
            iv = getrandbytes(16)
            ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
                pad(FLAG, AES.block_size))
            print("Ciphertext:", ciphertext.hex())
        elif option == "4":
            print("Bye bye!\n")
            break
        else:
            print("Invalid option")
        print()


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
