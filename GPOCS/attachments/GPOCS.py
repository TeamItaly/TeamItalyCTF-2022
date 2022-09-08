#!/usr/bin/env python3

import secrets
import os
import base64
import signal

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

TIMEOUT = 1200
FLAG = os.environ.get("FLAG", "flag{test}")
MAX_ROUNDS = 20
MAX_ATTEMPTS_PER_ROUND = 8
WORDS_PER_ROUND = 12

class RateLimitReachedException(Exception):
    pass


class Challenge:
    def __init__(self):
        with open('words.txt') as f:
            self.words = [line.strip() for line in f.readlines()]
        self.attempts = 0
        self.round = 0

    def new_round(self):
        self.round += 1
        self.attempts = 0
        self.round_words = []
        words = self.words[::]
        for _ in range(WORDS_PER_ROUND):
            word = secrets.choice(words)
            words.remove(word)
            self.round_words.append(word)
        self.generate_password()

    def generate_password(self):
        self.password = '-'.join([self.round_words[secrets.randbelow(12)]
                                 for _ in range(2)])
        self.salt = os.urandom(16)
        self.key = Scrypt(salt=self.salt, length=32, n=2**14,
                          r=8, p=1).derive(self.password.encode())

    def decrypt(self, ctxt) -> bool:
        self.attempts += 1

        ctxt = base64.b64decode(ctxt)
        nonce, ctxt = ctxt[:12], ctxt[12:]
        cipher = ChaCha20Poly1305(self.key)

        try:
            cipher.decrypt(nonce, ctxt, None)
        except:
            return False
        else:
            return True


def handle():
    chall = Challenge()

    print("Welcome to the GPOCS testing service. Here we test if the passwords we generate are good enough to be written on a post-it by the Italian PA and shown on live TV.")
    print("Press ENTER to begin.")

    input("")

    while True:
        chall.new_round()

        if chall.round > MAX_ROUNDS:
            print(
                f"Looks like our generator is not random enough... Here's a flag for your troubles: {FLAG}")
            return

        print(f"\nStarting round {chall.round}/{MAX_ROUNDS}")
        print(
            f"This round uses the following words: \n{' '.join(chall.round_words)}")
        print(
            f"This round uses the following salt (hex-encoded): {chall.salt.hex()}")

        success = False

        while True:
            print("Your options:")
            print("1) Send test message")
            print("2) Guess password")

            msg = input("> ")

            if msg == '1':
                if chall.attempts >= MAX_ATTEMPTS_PER_ROUND:
                    print(
                        "Sorry, you've reached your rate limit. You're on your own now.")
                    continue

                ctxt = input("Send your ciphertext (base64-encoded): ")

                if chall.decrypt(ctxt):
                    print("OK")
                else:
                    print("Nope.")

            elif msg == '2':
                ctxt = input("Send your password guess: ")

                if ctxt == chall.password:
                    print("Good job!")
                    success = True
                else:
                    print("Nope!")
                break
            else:
                print(f"Invalid choice")

        if success:
            continue
        else:
            break


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    handle()
