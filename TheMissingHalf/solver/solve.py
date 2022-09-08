from Crypto.Util.number import *
# from secret import FLAG
import random
from hashlib import md5


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
    t = list(long_to_bytes(x) + long_to_bytes(y))
    random.shuffle(t)
    return bytes_to_long(bytes(t))


def d(n):
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


def revE(msg: int) -> int:  # rsa
    n = 0x1702f4d2a98712defc05cb40b72a821479ccb9000a9bd698520082544b652bacfa721041f115da3a3cb8f4211a847706ae4dc9f048c7262a964e337bc47065de1059eccc87c19f662c21f9066805e5f75b3c62305395138d5eb71e9f9966297750ee17ccfcace1386abaf53434b264696744ae990bdebb17a4a56c4edc0cccfcf8da138fcf0c911f434d2d3e0b493b8fa9917f83f41273b4aaf7d631dabb66939f67fcb270e0a7156c7e66338027387e873c225991180fec96ea4fc0f9f88815010e5994d5f35ae21568d5641b00d44876762c392e9853045a5a92eb2354486f80946368f83469a7b37e621906f81f8005b126417fd716bcd79c84610dc093dd7575ebcf3af3d71a869830455d3ad6d68ad2254843320233e01f1cafdc73310f7ffb1deccb4df2fee6150a1a588867c5285c7049bf39e1a631badc81d61dda69e5d2e017235306ad46b0703e88a5c65807737a6a459231f5eb6bd6afd44fb46566c1
    p = 2911721007088133262675953106197241703556747554305425259320716892314498939605330257723180761563459946872506915178651543859508747846871417959638013334210124890497567604326390324762618539999256667220682352421111253679877478493941553844107359114872928940037671284003186268154810467080223359
    q = n // p
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))
    return pow(msg, d, n)


def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))


def polacco(password: str) -> int:
    stack = []
    func = {'a': (a, 2), 'b': (b, 2), 'c': (c, 3), 'd': (d, 1), 'e': (e, 1), 'f': (f, 1)}
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


def solve():
    random.seed(e(7))
    out = int(open('out.txt').read().split(':')[-1], 16)

    l = long_to_bytes(out)
    temp = long_to_bytes(b(3, d(c(1, 2, a(2, 7)))))

    # temp = long_to_bytes(160041365501716368448053427917678638214)
    while len(temp) < len(l):
        temp += temp
    temp = temp[:len(l)]
    temp = bytes_to_long(xor(temp, l))

    temp = revE(temp)

    temp2 = a(5, a(5, 3))

    print(xor(long_to_bytes(temp), long_to_bytes(temp2)))


solve()
