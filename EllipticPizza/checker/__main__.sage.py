

# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_91 = Integer(91); _sage_const_3 = Integer(3); _sage_const_57 = Integer(57); _sage_const_0 = Integer(0); _sage_const_6 = Integer(6); _sage_const_689824709835763661212917891210192229166873119806353925 = Integer(689824709835763661212917891210192229166873119806353925); _sage_const_2478485702646772354085217778801988934296596878299338050 = Integer(2478485702646772354085217778801988934296596878299338050); _sage_const_942903695767137584026537717052710977828250723819628138 = Integer(942903695767137584026537717052710977828250723819628138); _sage_const_364625566770303975901492217768553886851432032784755076 = Integer(364625566770303975901492217768553886851432032784755076); _sage_const_2742917099100796602246115112758864407275043210045673210 = Integer(2742917099100796602246115112758864407275043210045673210); _sage_const_1224220368752701250142143989282248366644465532537779451 = Integer(1224220368752701250142143989282248366644465532537779451); _sage_const_3027039163506222584359297393447359222232947335466083600 = Integer(3027039163506222584359297393447359222232947335466083600); _sage_const_3169601705630822879781127309238868216961138055829555931 = Integer(3169601705630822879781127309238868216961138055829555931); _sage_const_3490059421151589241282844776547134156509060455350829321 = Integer(3490059421151589241282844776547134156509060455350829321); _sage_const_1794875097282666540523000574016315517012678449510183952 = Integer(1794875097282666540523000574016315517012678449510183952); _sage_const_3164937069244528012501785994511807136863378511336753997 = Integer(3164937069244528012501785994511807136863378511336753997); _sage_const_1615640198356510736828007505990397689903302760897759569 = Integer(1615640198356510736828007505990397689903302760897759569); _sage_const_1359082117671312119351641025674270894687770763828316567 = Integer(1359082117671312119351641025674270894687770763828316567); _sage_const_1701631453787849568492693572465367443829807713991899911 = Integer(1701631453787849568492693572465367443829807713991899911); _sage_const_1743784037307975250157545016470187260457358261256646798 = Integer(1743784037307975250157545016470187260457358261256646798); _sage_const_2069327206845474638589006802971309729221166400917212890 = Integer(2069327206845474638589006802971309729221166400917212890); _sage_const_15012 = Integer(15012); _sage_const_8 = Integer(8); _sage_const_0xffffffff = Integer(0xffffffff); _sage_const_32 = Integer(32); _sage_const_16 = Integer(16); _sage_const_29 = Integer(29); _sage_const_1400 = Integer(1400); _sage_const_255 = Integer(255); _sage_const_19 = Integer(19); _sage_const_486662 = Integer(486662); _sage_const_7 = Integer(7); _sage_const_4 = Integer(4); _sage_const_64 = Integer(64); _sage_const_124312531532 = Integer(124312531532); _sage_const_30 = Integer(30); _sage_const_1337 = Integer(1337)
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import process, remote
from rcrack import Untwister
import os
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)
os.environ['TERM'] = 'alacritty'

load("castryck_decru_shortcut.sage")

debug = True

def generate_distortion_map(E):
    return E.isogeny(E.lift_x(ZZ(_sage_const_1 )), codomain=E)

def compute_final_curve(E, priv_key, P, Q):
    K = P + priv_key*Q
    phi = E.isogeny(K, algorithm="factored")
    E_final = phi.codomain()
    return E_final.j_invariant()

# Setup SIDH params
lA,a, lB,b = _sage_const_2 ,_sage_const_91 , _sage_const_3 ,_sage_const_57 
p = lA**a * lB**b - _sage_const_1 
Fp2 = GF(p**_sage_const_2 , modulus=x**_sage_const_2 +_sage_const_1 , names=('i',)); (i,) = Fp2._first_ngens(1)
E_start = EllipticCurve(Fp2, [_sage_const_0 ,_sage_const_6 ,_sage_const_0 ,_sage_const_1 ,_sage_const_0 ])
two_i = generate_distortion_map(E_start)
P2 = E_start([_sage_const_689824709835763661212917891210192229166873119806353925 *i + _sage_const_2478485702646772354085217778801988934296596878299338050 , _sage_const_942903695767137584026537717052710977828250723819628138 *i + _sage_const_364625566770303975901492217768553886851432032784755076 ])
Q2 = E_start([_sage_const_2742917099100796602246115112758864407275043210045673210 *i + _sage_const_1224220368752701250142143989282248366644465532537779451 , _sage_const_3027039163506222584359297393447359222232947335466083600 *i + _sage_const_3169601705630822879781127309238868216961138055829555931 ])
P3 = E_start([_sage_const_3490059421151589241282844776547134156509060455350829321 *i + _sage_const_1794875097282666540523000574016315517012678449510183952 , _sage_const_3164937069244528012501785994511807136863378511336753997 *i + _sage_const_1615640198356510736828007505990397689903302760897759569 ])
Q3 = E_start([_sage_const_1359082117671312119351641025674270894687770763828316567 *i + _sage_const_1701631453787849568492693572465367443829807713991899911 , _sage_const_1743784037307975250157545016470187260457358261256646798 *i + _sage_const_2069327206845474638589006802971309729221166400917212890 ])

HOST = os.environ.get("HOST", "elliptic-pizza.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", _sage_const_15012 ))
chall = remote(HOST, PORT)

def curve_from_str(curve_str: str):
    split_str = curve_str.split(" + ")
    a2 = eval(split_str[_sage_const_1 ].split('*x')[_sage_const_0 ])
    a4 = eval(split_str[_sage_const_2 ].split('*x')[_sage_const_0 ])
    a6 = eval(split_str[_sage_const_3 ].split()[_sage_const_0 ])
    if debug:
        print("a2 =", split_str[_sage_const_1 ].split('*x')[_sage_const_0 ])
        print("a4 =", split_str[_sage_const_2 ].split('*x')[_sage_const_0 ])
        print("a6 =", split_str[_sage_const_3 ].split()[_sage_const_0 ])
    E = EllipticCurve(Fp2, [_sage_const_0 , a2, _sage_const_0 , a4, a6])
    return E

def point_from_str(point_str: str, E):
    split_str = point_str.split('(')[_sage_const_1 ].split(')')[_sage_const_0 ].split(" : ")
    x = eval(split_str[_sage_const_0 ])
    y = eval(split_str[_sage_const_1 ])
    return E([x, y])

def attack(EA, PA, QA, EB, PB, QB):
    x = PB.weil_pairing(QB, _sage_const_2 **a)
    base = P2.weil_pairing(Q2, _sage_const_2 **a)
    sol = log(x, base)
    assert base**sol == x
    sol = Zmod(_sage_const_2 **a)(_sage_const_3 **b)**-_sage_const_1 *sol
    possible_bs = sol.nth_root(_sage_const_2 ,all=True)
    possible_bs = [possible_bs[_sage_const_0 ], possible_bs[_sage_const_2 ]]
    # iv = ciphertext[:16]
    # ciphertext = ciphertext[16:]

    for hope in possible_bs:
        origin_PB = int(Zmod(_sage_const_2 **a)(hope)**-_sage_const_1 )*PB
        origin_QB = int(Zmod(_sage_const_2 **a)(hope)**-_sage_const_1 )*QB
        try:
            priv_B = CastryckDecruAttack(E_start, P2, Q2, EB, origin_PB, origin_QB, two_i, num_cores=_sage_const_1 )
            j = compute_final_curve(EA, priv_B, PA, QA)
            shared = int(j.polynomial().coefficients()[_sage_const_0 ]).to_bytes(int(p).bit_length()//_sage_const_8  + _sage_const_1 , "big")
            key = sha256(shared).digest()
            print(f"{key.hex() = }")
            return priv_B, hope, key
            # cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            # plain = unpad(cipher.decrypt(ciphertext), AES.block_size)
            # if plaintext != "":
            #     if plain == plaintext:
        except:
            print("Nope")

def split_in_words(r, n):
    words = []
    for _ in range(n):
        words.append(bin(r & _sage_const_0xffffffff )[_sage_const_2 :].zfill(_sage_const_32 ))
        r >>= _sage_const_32 
    return words


def encrypt_message(plaintext, key):
    iv = os.urandom(_sage_const_16 )
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv.hex() + ciphertext.hex()

def decrypt_message(ciphertext, key):
    iv = ciphertext[:_sage_const_16 ]
    ciphertext = ciphertext[_sage_const_16 :]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def decrypt_conversation(key):
    words = []
    chall.sendlineafter(b"> ", b'2')
    chall.recvline()
    for _ in range(_sage_const_29 ):
        for _ in range(_sage_const_3 ):
            chall.recvline()
        ciphertext = bytes.fromhex(chall.recvline().decode().split()[-_sage_const_1 ])
        plain = decrypt_message(ciphertext, key)
        ciphertext = bytes.fromhex(chall.recvline().decode().split()[-_sage_const_1 ])
        if plain == "Send me r: ":
            r = int(decrypt_message(ciphertext, key))
            words.extend(split_in_words(r, _sage_const_8 ))
            # print(f"{r = }")
        else:
            for _ in range(_sage_const_8 ):
                words.append('?'*_sage_const_32 )
        chall.recvline()
        words.append('?'*_sage_const_32 )
    chall.recvline()
    return words

def get_words(words, key):
    while len([w for w in words if '?' not in w]) < _sage_const_1400 :
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
    try:
        int(n)
        return [int(n), _sage_const_0 ]
    except:
        coefs = n.polynomial().coefficients()
        return coefs

italian_p = _sage_const_2 **_sage_const_255  - _sage_const_19  
italian_Fp = GF(italian_p)
italian_E = EllipticCurve(italian_Fp, [_sage_const_0 , _sage_const_486662 , _sage_const_0 , _sage_const_1 , _sage_const_0 ])

def get_flag():
    chall.recvline()
    chall.recvline()
    chall.recvline()
    italian_G = point_from_str(chall.recvline().decode(), italian_E)
    italian_pub_key = point_from_str(chall.recvline().decode(), italian_E)
    for _ in range(_sage_const_7 ):
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
    for _ in range(_sage_const_4 ):
        words.append('?'*_sage_const_32 )

    # Italian params
    EB = curve_from_str(chall.recvline().decode())
    PB = point_from_str(chall.recvline().decode(), EB)
    QB = point_from_str(chall.recvline().decode(), EB)
    if debug:
        print(f"{EB = }")
        print(f"{PB = }")
        print(f"{QB = }")

    # ciphertext = bytes.fromhex(chall.recvline().decode().split()[-1])
    priv_B, _b, key = attack(EA, PA, QA, EB, PB, QB)
    words.extend(split_in_words(priv_B, _sage_const_2 ))
    for _ in range(_sage_const_2 ):
        words.append('?'*_sage_const_32 )
    if debug:
        print(f"{priv_B = }")
        
    rand = get_rand(words, key)
    chall.sendlineafter(b"> ", b'1')
    priv_sorbillo = rand.getrandbits(_sage_const_64 )
    _a = _sage_const_3 *rand.getrandbits(_sage_const_64 ) + _sage_const_1 
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
    priv_key = _sage_const_124312531532 
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
    xP_2, xP_1 = elem_to_list(PB[_sage_const_0 ])
    yP_2, yP_1 = elem_to_list(PB[_sage_const_1 ])
    xQ_2, xQ_1 = elem_to_list(QB[_sage_const_0 ])
    yQ_2, yQ_1 = elem_to_list(QB[_sage_const_1 ])

    chall.sendlineafter(b"xP_1: ", str(xP_1).encode())
    chall.sendlineafter(b"xP_2: ", str(xP_2).encode())
    chall.sendlineafter(b"yP_1: ", str(yP_1).encode())
    chall.sendlineafter(b"yP_2: ", str(yP_2).encode())
    chall.sendlineafter(b"xQ_1: ", str(xQ_1).encode())
    chall.sendlineafter(b"xQ_2: ", str(xQ_2).encode())
    chall.sendlineafter(b"yQ_1: ", str(yQ_1).encode())
    chall.sendlineafter(b"yQ_2: ", str(yQ_2).encode())

    j = compute_final_curve(EA, priv_key, PA, QA)
    shared = int(j.polynomial().coefficients()[_sage_const_0 ]).to_bytes(int(p).bit_length()//_sage_const_8  + _sage_const_1 , "big")
    key = sha256(shared).digest()

    chall.recvline()
    for _ in range(_sage_const_30 ):
        chall.recvline()
        c = rand.getrandbits(_sage_const_1 )
        if c:
            A = -italian_pub_key + _sage_const_1337 *italian_G
        else:
            A = _sage_const_1337 *italian_G
        chall.recvline()
        chall.sendline(encrypt_message(str(A[_sage_const_0 ]).encode(), key))
        chall.recvline()
        chall.sendline(encrypt_message(str(A[_sage_const_1 ]).encode(), key))
        chall.recvline()
        chall.sendline(encrypt_message(b'1337', key))
        print(decrypt_message(bytes.fromhex(chall.recvline().decode()), key))
    ciphertext = bytes.fromhex(chall.recvline().decode())
    plain = decrypt_message(ciphertext, key)
    print(f"{plain = }")

get_flag()

