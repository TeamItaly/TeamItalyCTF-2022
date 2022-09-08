# TeamItaly CTF 2022

## The missing half (17 solves)

A python script and a output file are given. The script uses a password (which is given) that is used by a _redacted_ function.
The challenge is to understand what the funcion did and to reverse it.

### Solution

From the name of the function one can understand that the password is in Polish notation and from the order of the digits (mostly in front) and letters (mostly at the end) that it's a reverse polish notation.

The password therefore is equivalent to `c( b(e(a(0,8)),e(7)), b(3,d(c(1,2,a(2,7)))), e(f(a(5,a(5,3)))) )`, let's analyze c and his 3 arguments.

The first one returns 0 and sets the random seed to `e(7)`;
The second one is just a number and all the variables to calculate it are given, the problem is that the function d is very slow so we have to substitute it with another called _fastd_;

`d` is the [A028365](http://oeis.org/A028365) sequence on OEIS wich has a different definition

$$\left( \sum_{k=1}^n 2^k -1 \right)^2 *2^{((n^2+n)/2))}$$
wich is faster to compute.

The third uses the `f` function wich uses the flag so can't be calculated completely, we can easely compute until that point (`a(5,a(5,3))`), then compute the output of `f` from the given output and recover the flag,
to do so we know that when the first argument of c is 0 the other two are xored, so we xor the second argument with the output;
now to reach f we need to reverse e wich is RSA.

To decrypt RSA we need to factor n, how to do so is easy if you see the number in a divverent base:

the number in base 16
`0x1702f4d2a98712defc05cb40b72a821479ccb9000a9bd698520082544b652bacfa721041f115da3a3cb8f4211a847706ae4dc9f048c7262a964e337bc47065de1059eccc87c19f662c21f9066805e5f75b3c62305395138d5eb71e9f9966297750ee17ccfcace1386abaf53434b264696744ae990bdebb17a4a56c4edc0cccfcf8da138fcf0c911f434d2d3e0b493b8fa9917f83f41273b4aaf7d631dabb66939f67fcb270e0a7156c7e66338027387e873c225991180fec96ea4fc0f9f88815010e5994d5f35ae21568d5641b00d44876762c392e9853045a5a92eb2354486f80946368f83469a7b37e621906f81f8005b126417fd716bcd79c84610dc093dd7575ebcf3af3d71a869830455d3ad6d68ad2254843320233e01f1cafdc73310f7ffb1deccb4df2fee6150a1a588867c5285c7049bf39e1a631badc81d61dda69e5d2e017235306ad46b0703e88a5c65807737a6a459231f5eb6bd6afd44fb46566c1`

in base 17 is
`gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggegggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggf0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004`

As for a mersenne prime is easy to brute force the right prime number, in this case `p = 17 ** 232 -2`.

At the end we can recover the input and the output of `f` and so the flag.

### Exploit

```python

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


def c(z: int, x: int, y: int) -> int:
    if z:
        return random.randint(x ** 11, x ** 11 + y)
    x = long_to_bytes(x)
    y = long_to_bytes(y)
    while len(x) < len(y):
        x += x
    x = x[:len(y)]
    return bytes_to_long(xor(x, y))


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
    out = int(
        '69699507fd48efde364bab82106f89d23d22e463631a77941cfe29863229a40be8ba9ea548323b183bc37e4d7b151e8b60fac7d657185dfd1b75eebc2701c21bd3901f800145e76b1d48789428c7c3e8f7bc0aa11232ee076262d4f3c9b84b2a43e3da768e2f7622d645fa3bb94e65e64744b977f260ba1fd0956330c3cfc2fbddf350db366c2da5d72f91eb23905bc1b714b66460d726af257ff37d60897b33778d74c9a1e5dbf8c15390a5d65114c738f6812b39ec42afc00a873d866166411f2d4c9a69fce5aca631af87f4a6449282664e2a8ab79f5376486cf0f9fcb226e76b735dda222a024fda883352b8e24fee309f2057c7472a58a8aac886b9a1889e9b1f8d2306b493c4e16f3401a01263828a08e2070b4cdc6dd398bcac17d707847325064d4bf6dcfa9e683cee3c126eb4ad753997ae66792b71f83f835524ad6da5e25b3dabc21e541cd049bc038b7ced304c1012fe67919619c28f593940c5cb9c',
        16)

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


```
