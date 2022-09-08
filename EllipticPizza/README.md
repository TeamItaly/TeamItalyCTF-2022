# TeamItaly CTF 2022

## Elliptic Pizza (2 solves)

All italians have a secret key to order a special pizza at Sorbillo. It's impossible to fool them, you can't even read their conversations...

## Solution

### Passing the zero knowledge proof

The goal of the challenge is to pass the zero knowledge proof to get the flag from Sorbillo. The only possible ways to pass it are to discover the `italian_private_key` or to guess the coin tosses and send an appropriate value of `A`:

1. If `coin == 0` we can compute a random `r` and send `A = r*italian_G` and responde to the challenge with `r`.
2. If `coin == 1` we can compute a random `r` and send `A = -italian_pub_key + r*italian_G`. Since Sorbillo will check if `m*italian_G == A + italian_pub_key`, we can just respond with `r` and pass the check.

From the source code we see that `coin = random.getrandbits(1)`, but, since `random` uses the Mersenne Twister, knowing enough random bits we can predict the outputs and pass the verification.

The only source of randomness is from the conversations we can intercept, but these are encrypted with AES and the only way to decrypt them is breaking the key exchange.

### Breaking SIDH (another time)

The key for encrypting the conversations is derived through a variant of SIDH: SIDH with masked torsion point images. The paper where this idea is proposed is https://eprint.iacr.org/2022/1054. This doesn't allow the Castryck-Decru attack. But, computing the weil pairing of the masked torsion points we have:
$$e(b\cdot PB, b\cdot QB) = e(b\cdot \phi(P2), b\cdot \phi(Q2)) = e(P2, Q2)^{(b^2\cdot deg(\phi))}.$$
Hence, letting B be the order of P2 and Q2, by computing the discrete logarithm of $e(b\cdot \phi(PB), b\cdot \phi(QB))$ with base $e(P2, Q2)$ we can derive:
$$b^2\cdot deg(\phi) \mod(B) => b^2 \mod(B).$$
In this case we know that $B = 2^a$, thus we have only 4 square roots modulo (B) and, by bruteforcing all of them and trying the Castryck-Decru attack, we can recover the secret key and derive the encryption key used for AES. (In the paper the variant proposed uses torsion points with an order that has a large number of prime factors: this way one has an exponential number import square roots modulo $B$ and this attack becomes infeasible.)

Once we have the shared key we can start decrypting the conversations and getting enough bits from `random.getrandbits` and recover the Mersenne Twister seed. At this point we can either proceed by predicting the challenges as said before or by recovering the `italian_private_key` by intercepting some other conversations and predicting `r` (suggest you to try also this way to discover what's the key).

### Exploit

```python

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import process, remote
from rcrack import Untwister
import os
import warnings


# https://github.com/jack4818/Castryck-Decru-SageMath
# Thanks to all the people who contributed to this <3
# For the story of the implementation: https://research.nccgroup.com/2022/08/08/implementing-the-castryck-decru-sidh-key-recovery-attack-in-sagemath/
load("castryck_decru_shortcut.sage")

debug = True

def generate_distortion_map(E):
    return E.isogeny(E.lift_x(ZZ(1)), codomain=E)

def compute_final_curve(E, priv_key, P, Q):
    K = P + priv_key*Q
    phi = E.isogeny(K, algorithm="factored")
    E_final = phi.codomain()
    return E_final.j_invariant()

# Setup SIDH params
lA,a, lB,b = 2,91, 3,57
p = lA^a * lB^b - 1
Fp2.<i> = GF(p^2, modulus=x^2+1)
E_start = EllipticCurve(Fp2, [0,6,0,1,0])
two_i = generate_distortion_map(E_start)
P2 = E_start([689824709835763661212917891210192229166873119806353925*i + 2478485702646772354085217778801988934296596878299338050, 942903695767137584026537717052710977828250723819628138*i + 364625566770303975901492217768553886851432032784755076])
Q2 = E_start([2742917099100796602246115112758864407275043210045673210*i + 1224220368752701250142143989282248366644465532537779451, 3027039163506222584359297393447359222232947335466083600*i + 3169601705630822879781127309238868216961138055829555931])
P3 = E_start([3490059421151589241282844776547134156509060455350829321*i + 1794875097282666540523000574016315517012678449510183952, 3164937069244528012501785994511807136863378511336753997*i + 1615640198356510736828007505990397689903302760897759569])
Q3 = E_start([1359082117671312119351641025674270894687770763828316567*i + 1701631453787849568492693572465367443829807713991899911, 1743784037307975250157545016470187260457358261256646798*i + 2069327206845474638589006802971309729221166400917212890])

HOST = os.environ.get("HOST", "elliptic-pizza.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 15012))
chall = remote(HOST, PORT)

def curve_from_str(curve_str: str):
    split_str = curve_str.split(" + ")
    a2 = eval(split_str[1].split('*x')[0])
    a4 = eval(split_str[2].split('*x')[0])
    a6 = eval(split_str[3].split()[0])
    if debug:
        print("a2 =", split_str[1].split('*x')[0])
        print("a4 =", split_str[2].split('*x')[0])
        print("a6 =", split_str[3].split()[0])
    E = EllipticCurve(Fp2, [0, a2, 0, a4, a6])
    return E

def point_from_str(point_str: str, E):
    split_str = point_str.split('(')[1].split(')')[0].split(" : ")
    x = eval(split_str[0])
    y = eval(split_str[1])
    return E([x, y])

def attack(EA, PA, QA, EB, PB, QB):
    x = PB.weil_pairing(QB, 2**a)
    base = P2.weil_pairing(Q2, 2**a)
    sol = log(x, base)
    assert base**sol == x
    sol = Zmod(2**a)(3**b)^-1*sol
    possible_bs = sol.nth_root(2,all=True)
    possible_bs = [possible_bs[0], possible_bs[2]]

    for hope in possible_bs:
        origin_PB = int(Zmod(2**a)(hope)^-1)*PB
        origin_QB = int(Zmod(2**a)(hope)^-1)*QB
        try:
            priv_B = CastryckDecruAttack(E_start, P2, Q2, EB, origin_PB, origin_QB, two_i, num_cores=1)
            j = compute_final_curve(EA, priv_B, PA, QA)
            shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length()//8 + 1, "big")
            key = sha256(shared).digest()
            print(f"{key.hex() = }")
            return priv_B, hope, key
        except:
            print("Nope")

# This is to split the numbers in the right format for the Untwister
def split_in_words(random_number, num_of_words):
    words = []
    for _ in range(num_of_words):
        words.append(bin(random_number & 0xffffffff)[2:].zfill(32))
        random_number >>= 32
    return words


def encrypt_message(plaintext, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv.hex() + ciphertext.hex()

def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def decrypt_conversation(key):
    words = []
    chall.sendlineafter(b"> ", b'2')
    chall.recvline()
    for _ in range(29):
        for _ in range(3):
            chall.recvline()
        ciphertext = bytes.fromhex(chall.recvline().decode().split()[-1])
        plain = decrypt_message(ciphertext, key)
        ciphertext = bytes.fromhex(chall.recvline().decode().split()[-1])
        if plain == "Send me r: ":
            r = int(decrypt_message(ciphertext, key))
            words.extend(split_in_words(r, 8))
        else:
            for _ in range(8):
                words.append('?'*32)
        chall.recvline()
        words.append('?'*32)
    chall.recvline()
    return words

def get_words(words, key):
    while len([w for w in words if '?' not in w]) < 1400:
        words.extend(decrypt_conversation(key))
        print(f"[+] Known words: {len([w for w in words if '?' not in w])}")
    return words

def get_rand(words, key):
    words = get_words(words, key)
    cracker = Untwister()
    for w in words:
        cracker.submit(w)
    rand = cracker.get_random()
    return rand

def elem_to_list(n):
    # I know, probably there is something better, but it works
    try:
        int(n)
        return [int(n), 0]
    except:
        # For numbers of the form 3*i this doesn't work, but it's very unlikely for what this function is used
        coefs = n.polynomial().coefficients()
        return coefs

# Italian parameters
italian_p = 2^255 - 19
italian_Fp = GF(italian_p)
italian_E = EllipticCurve(italian_Fp, [0, 486662, 0, 1, 0])

def get_flag():
    chall.recvline()
    chall.recvline()
    chall.recvline()
    italian_G = point_from_str(chall.recvline().decode(), italian_E)
    italian_pub_key = point_from_str(chall.recvline().decode(), italian_E)
    for _ in range(7):
        chall.recvline()

    words = []
    # Sorbillo params
    EA = curve_from_str(chall.recvline().decode())
    PA = point_from_str(chall.recvline().decode(), EA)
    QA = point_from_str(chall.recvline().decode(), EA)
    if debug:
        print(f"{EA = }")
        print(f"{PA = }")
        print(f"{QA = }")
    for _ in range(4):
        words.append('?'*32)

    # Italian params
    EB = curve_from_str(chall.recvline().decode())
    PB = point_from_str(chall.recvline().decode(), EB)
    QB = point_from_str(chall.recvline().decode(), EB)
    if debug:
        print(f"{EB = }")
        print(f"{PB = }")
        print(f"{QB = }")

    priv_B, _b, key = attack(EA, PA, QA, EB, PB, QB)
    words.extend(split_in_words(priv_B, 2))
    for _ in range(2):
        words.append('?'*32)
    if debug:
        print(f"{priv_B = }")

    rand = get_rand(words, key)
    chall.sendlineafter(b"> ", b'1')
    priv_sorbillo = rand.getrandbits(64)
    _a = 3*rand.getrandbits(64) + 1
    K = P2 + priv_sorbillo*Q2
    phi = E_start.isogeny(K, algorithm="factored")
    EA = phi.codomain()
    print(f"{EA = }")
    print(chall.recvline().decode())
    PA, QA = _a*phi(P3), _a*phi(Q3)
    print(f"{PA = }")
    print(f"{QA = }")
    print(chall.recvline().decode())
    print(chall.recvline().decode())
    chall.recvline()

    # These was so useless, have no idea why I did it... :(
    priv_key = 1337
    K = P3 + priv_key*Q3
    phi = E_start.isogeny(K, algorithm="factored")
    EB = phi.codomain()
    a1_2, a1_1 = elem_to_list(EB.a1())
    a2_2, a2_1 = elem_to_list(EB.a2())
    a3_2, a3_1 = elem_to_list(EB.a3())
    a4_2, a4_1 = elem_to_list(EB.a4())
    a6_2, a6_1 = elem_to_list(EB.a6())
    chall.sendlineafter(b"a1_1: ", str(a1_1).encode())
    chall.sendlineafter(b"a1_2: ", str(a1_2).encode())
    chall.sendlineafter(b"a2_1: ", str(a2_1).encode())
    chall.sendlineafter(b"a2_2: ", str(a2_2).encode())
    chall.sendlineafter(b"a3_1: ", str(a3_1).encode())
    chall.sendlineafter(b"a3_2: ", str(a3_2).encode())
    chall.sendlineafter(b"a4_1: ", str(a4_1).encode())
    chall.sendlineafter(b"a4_2: ", str(a4_2).encode())
    chall.sendlineafter(b"a6_1: ", str(a6_1).encode())
    chall.sendlineafter(b"a6_2: ", str(a6_2).encode())

    PB, QB = phi(P2), phi(Q2)
    xP_2, xP_1 = elem_to_list(PB[0])
    yP_2, yP_1 = elem_to_list(PB[1])
    xQ_2, xQ_1 = elem_to_list(QB[0])
    yQ_2, yQ_1 = elem_to_list(QB[1])

    chall.sendlineafter(b"xP_1: ", str(xP_1).encode())
    chall.sendlineafter(b"xP_2: ", str(xP_2).encode())
    chall.sendlineafter(b"yP_1: ", str(yP_1).encode())
    chall.sendlineafter(b"yP_2: ", str(yP_2).encode())
    chall.sendlineafter(b"xQ_1: ", str(xQ_1).encode())
    chall.sendlineafter(b"xQ_2: ", str(xQ_2).encode())
    chall.sendlineafter(b"yQ_1: ", str(yQ_1).encode())
    chall.sendlineafter(b"yQ_2: ", str(yQ_2).encode())

    j = compute_final_curve(EA, priv_key, PA, QA)
    shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length()//8 + 1, "big")
    key = sha256(shared).digest()

    chall.recvline()
    for _ in range(30):
        chall.recvline()
        c = rand.getrandbits(1)
        if c:
            A = -italian_pub_key + 1337*italian_G
        else:
            A = 1337*italian_G
        chall.recvline()
        chall.sendline(encrypt_message(str(A[0]).encode(), key))
        chall.recvline()
        chall.sendline(encrypt_message(str(A[1]).encode(), key))
        chall.recvline()
        chall.sendline(encrypt_message(b'1337', key))
        print(decrypt_message(bytes.fromhex(chall.recvline().decode()), key))
    ciphertext = bytes.fromhex(chall.recvline().decode())
    plain = decrypt_message(ciphertext, key)
    print(f"{plain = }")

get_flag()
```
