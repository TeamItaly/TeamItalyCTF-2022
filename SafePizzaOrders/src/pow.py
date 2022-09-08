import random
import string
import hashlib
import os

num = os.environ.get("POW", "6")
num = int(num)

if num <= 0:  # Skip POW
    exit(0)

letters = string.ascii_lowercase+string.ascii_uppercase
p = ''.join(random.choice('0123456789abcdef') for _ in range(num))
starting_string = ''.join(random.choice(letters) for _ in range(10))
print("Give me a string starting in {} such that its sha256sum ends in {}.".format(
    starting_string, p))
l = input().strip()
if hashlib.sha256(l.encode('ascii')).hexdigest()[-num:] != p or l[:10] != starting_string:
    print("Wrong PoW")
    exit(1)
exit(0)
