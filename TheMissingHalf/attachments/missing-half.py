#!/usr/bin/env python3

from Crypto.Util.number import *
import os
import random
from hashlib import md5

FLAG = os.environ.get("FLAG", "flag{test}")


def a(x, y) -> int:
    return x ** y


def b(f: int, x: int) -> int:  # caller
    func = [random.seed, getPrime, isPrime, md5]
    if f == 3:
        return bytes_to_long(func[f](long_to_bytes(x)).digest())
    r = func[f](x)
    return int(r) if r else 0


def c(z: int, x: int, y: int) -> int:  # random
    if z:
        return random.randint(x ** 11, x ** 11 + y)
    x = long_to_bytes(x)
    y = long_to_bytes(y)
    while len(x) < len(y):
        x += x
    x = x[:len(y)]
    return bytes_to_long(xor(x, y))


def d(x: int) -> int:
    if x == 1:
        return 1
    if x == 2:
        return 2
    if x == 3:
        return 24
    return (6 * d(x - 1) ** 2 * d(x - 3) - 8 * d(x - 1) * d(x - 2) ** 2) // (d(x - 2) * d(x - 3))


def fastd(n):
    n = n - 1
    temp = 1
    for i in range(1, n + 1):
        temp *= (2 ** i) - 1
    esp = 2 ** ((n ** 2 + n) // 2)
    return temp * esp


def e(msg: int) -> int:  # rsa
    n = 0x1702f4d2a98712defc05cb40b72a821479ccb9000a9bd698520082544b652bacfa721041f115da3a3cb8f4211a847706ae4dc9f048c7262a964e337bc47065de1059eccc87c19f662c21f9066805e5f75b3c62305395138d5eb71e9f9966297750ee17ccfcace1386abaf53434b264696744ae990bdebb17a4a56c4edc0cccfcf8da138fcf0c911f434d2d3e0b493b8fa9917f83f41273b4aaf7d631dabb66939f67fcb270e0a7156c7e66338027387e873c225991180fec96ea4fc0f9f88815010e5994d5f35ae21568d5641b00d44876762c392e9853045a5a92eb2354486f80946368f83469a7b37e621906f81f8005b126417fd716bcd79c84610dc093dd7575ebcf3af3d71a869830455d3ad6d68ad2254843320233e01f1cafdc73310f7ffb1deccb4df2fee6150a1a588867c5285c7049bf39e1a631badc81d61dda69e5d2e017235306ad46b0703e88a5c65807737a6a459231f5eb6bd6afd44fb46566c1
    e = 0x10001
    return pow(msg, e, n)


def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))


def f(x: int) -> int:
    return bytes_to_long(xor(long_to_bytes(x), FLAG.encode()))


def Lukasiewicz(password: str) -> int:
    stack = []
    func = {'a': (a, 2), 'b': (b, 2), 'c': (c, 3),
            'd': (fastd, 1), 'e': (e, 1), 'f': (f, 1)}
    for t in password:
        if t.isdigit():
            stack.append(int(t))
        else:
            args = []
            for _ in range(func[t][1]):
                args.append(stack.pop())
            args.reverse()
            tmp = func[t][0](*args)
            stack.append(tmp)
    return stack.pop()


with open('missing-half.py.out', 'w') as file:
    password = '08ae7eb31227acdb553aafec'
    file.write('out:' + hex(Lukasiewicz(password)))
