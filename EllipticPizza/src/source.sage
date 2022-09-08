from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import urandom
import os
import random
from secret import italian_priv_key
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

italian_p = 2^255 - 19 
italian_Fp = GF(italian_p)
italian_E = EllipticCurve(italian_Fp, [0, 486662, 0, 1, 0])
italian_G = italian_E.gens()[0]
italian_G_order = italian_G.order()
italian_pub_key = italian_priv_key*italian_G

special_pizza = os.environ.get("FLAG", "flag{test}")

def generate_torsion_points(E, a, b):
    def get_l_torsion_basis(E, l):
        n = (p+1) // l
        return (n*G for G in E.gens())

    P2, Q2 = get_l_torsion_basis(E, 2**a)
    P3, Q3 = get_l_torsion_basis(E, 3**b)

    return P2, Q2, P3, Q3

lA,a, lB,b = 2,91, 3,57
p = lA^a * lB^b - 1
Fp2.<i> = GF(p^2, modulus=x^2+1)
E_start = EllipticCurve(Fp2, [0,6,0,1,0])
P2, Q2, P3, Q3 = generate_torsion_points(E_start, a, b)

class Sorbillo():
    def __init__(self):
        pass

    def generate_key_pair(self, E_start, a, b, P2, Q2, P3, Q3):
        # generate private key
        self.priv_key = random.getrandbits(64)
        
        # No Castryck-Decru anymore
        _a = 3*random.getrandbits(64) + 1

        K = P2 + self.priv_key*Q2
        phi = E_start.isogeny(K, algorithm="factored")
        E = phi.codomain()

        PA, QA = _a*phi(P3), _a*phi(Q3)

        return E, PA, QA

    def generate_shared_key(self, E, P, Q):
        K = P + self.priv_key*Q
        phi = E.isogeny(K, algorithm="factored")
        E_final = phi.codomain()
        j = E_final.j_invariant()
        self.shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length()//8 + 1, "big")
        self.key = sha256(self.shared).digest()

    def encrypt_message(self, msg):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))
        return iv.hex() + ciphertext.hex()

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

    def verify_italianity(self):

        print(self.encrypt_message("Prove me you are a true Italian!"))
        for j in range(30):
            print(self.encrypt_message("Compute A = r*italian_G with a random r"))
            enc_Ax = bytes.fromhex(input(self.encrypt_message("A.x = ") + "\n"))
            Ax = int(self.decrypt_message(enc_Ax))
            enc_Ay = bytes.fromhex(input(self.encrypt_message("A.y = ") + "\n"))
            Ay = int(self.decrypt_message(enc_Ay))
            try:
                A = italian_E([Ax, Ay])
            except:
                print(self.encrypt_message(f"Are you trying to fool me?"))
                return False
            coin = random.getrandbits(1)
            if coin:
                enc_m = bytes.fromhex(input(self.encrypt_message("Send me r + italian_priv_key: ") + "\n"))
                m = int(self.decrypt_message(enc_m))
                if m*italian_G != A + italian_pub_key:
                    print(self.encrypt_message(f"Definitely not a true Italian!"))
                    return False
                else:
                    print(self.encrypt_message(f"You are {int(j/0.3)}% italian")   )
            else:
                enc_r = bytes.fromhex(input(self.encrypt_message("Send me r: ") + "\n"))
                r = int(self.decrypt_message(enc_r))
                if r*italian_G != A:
                    print(self.encrypt_message(f"Are you trying to fool me?"))
                    return False
                else:
                    print(self.encrypt_message(f"You are {int(j/0.3)}% italian")   )
        print(self.encrypt_message(f"Benvenuto italiano! Ecco la nostra pizza migliore: {special_pizza}"))
        return True

class Italiano():
    def __init__(self, italian_priv_key):
        self.italian_key = italian_priv_key

    def generate_key_pair(self, E_start, a, b, P2, Q2, P3, Q3):
        # generate private key
        self.priv_key = random.getrandbits(64)
        
        # No Castryck-Decru anymore
        _b = 2*random.getrandbits(64) + 1

        K = P3 + self.priv_key*Q3
        phi = E_start.isogeny(K, algorithm="factored")
        E = phi.codomain()

        PB, QB = _b*phi(P2), _b*phi(Q2)

        return E, PB, QB

    
    def generate_shared_key(self, E, P, Q):
        K = P + self.priv_key*Q
        phi = E.isogeny(K, algorithm="factored")
        E_final = phi.codomain()
        j = E_final.j_invariant()
        self.shared = int(j.polynomial().coefficients()[0]).to_bytes(int(p).bit_length()//8 + 1, "big")
        self.key = sha256(self.shared).digest()

    def encrypt_message(self, msg):
        iv = urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(msg.encode(), AES.block_size))
        return iv.hex() + ciphertext.hex()

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

def intercepted_conversation(sorbillo, italiano):


    print("[Sorbillo] " + sorbillo.encrypt_message("Prove me you are a true Italian!"))
    for j in range(29):
        print("[Sorbillo] " + sorbillo.encrypt_message("Compute A = r*italian_G with a random r"))
        r = random.getrandbits(256)
        A = r*italian_G
        enc_Ax = italiano.encrypt_message(str(A[0]))
        print("[Italiano] " + enc_Ax)
        enc_Ay = italiano.encrypt_message(str(A[1]))
        print("[Italiano] " + enc_Ay)
        coin = random.getrandbits(1)
        if coin:
            print("[Sorbillo] " + sorbillo.encrypt_message("Send me r + italian_priv_key: "))
            m = r + italiano.italian_key
            print("[Italiano] " + italiano.encrypt_message(str(m)))
            if m*italian_G != A + italian_pub_key:
                print("[Sorbillo] " + sorbillo.encrypt_message("Definitely not a true Italian!"))
                return
            else:
                print("[Sorbillo] " + sorbillo.encrypt_message(f"You are {int(j/0.3)}% italian"))
        else:
            print("[Sorbillo] " + sorbillo.encrypt_message("Send me r: "))
            print("[Italiano] " + italiano.encrypt_message(str(r)))
            if r*italian_G != A:
                print("[Sorbillo] " + sorbillo.encrypt_message("Are you trying to fool me?"))
                return
            else:
                print("[Sorbillo] " + sorbillo.encrypt_message(f"You are {int(j/0.3)}% italian"))
    print("[Italiano] " + italiano.encrypt_message("Oh no, the pasta is ready, need to go!"))
    return

def order_pizza():
    sorbillo = Sorbillo()
    EA, PA, QA = sorbillo.generate_key_pair(E_start, a, b, P2, Q2, P3, Q3)
    print(f"{EA = }")
    print(f"{PA = }")
    print(f"{QA = }")
    print("Send me your curve coefficients as EB: y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a5, with aj = aj_1*i + aj_2")
    a1_1 = int(input("a1_1: "))
    a1_2 = int(input("a1_2: "))
    a1 = a1_1*i + a1_2
    a2_1 = int(input("a2_1: "))
    a2_2 = int(input("a2_2: "))
    a2 = a2_1*i + a2_2
    a3_1 = int(input("a3_1: "))
    a3_2 = int(input("a3_2: "))
    a3 = a3_1*i + a3_2
    a4_1 = int(input("a4_1: "))
    a4_2 = int(input("a4_2: "))
    a4 = a4_1*i + a4_2
    a6_1 = int(input("a6_1: "))
    a6_2 = int(input("a6_2: "))
    a6 = a6_1*i + a6_2
    EB = EllipticCurve(Fp2, [a1, a2, a3, a4, a6])
    print("Send me PB and QB as PB = (xP, yP, 1) and QB = (xQ, yQ, 1) with xP = xP_1*i + xP_2")
    xP_1 = int(input("xP_1: "))
    xP_2 = int(input("xP_2: "))
    xP = xP_1*i + xP_2
    yP_1 = int(input("yP_1: "))
    yP_2 = int(input("yP_2: "))
    yP = yP_1*i + yP_2
    try:
        PB = EB([xP, yP])
    except:
        return
    xQ_1 = int(input("xQ_1: "))
    xQ_2 = int(input("xQ_2: "))
    xQ = xQ_1*i + xQ_2
    yQ_1 = int(input("yQ_1: "))
    yQ_2 = int(input("yQ_2: "))
    yQ = yQ_1*i + yQ_2
    try:
        QB = EB([xQ, yQ])
    except:
        return
    sorbillo.generate_shared_key(EB, PB, QB)
    sorbillo.verify_italianity()

def main():
    print("Only true italians can order a special pizza at Sorbillo. All the conversations are encrypted using the most advanced cryptography and the italianity is checked through an unbreakable protocol!")
    print("All the italians have a secret key used to verify their italianity. These are the public parameters:")
    print(f"{italian_E = }")
    print(f"{italian_G = }")
    print(f"{italian_pub_key = }")
    print("And these are the parameters used by Sorbillo to encrypt their conversations:")
    print(f"{E_start = }")
    print(f"{P2 = }")
    print(f"{Q2 = }")
    print(f"{P3 = }")
    print(f"{Q3 = }")

    print("And this is the key exchenge with an italiano we intercepted:")
    sorbillo = Sorbillo()
    italiano = Italiano(italian_priv_key)

    EA, PA, QA = sorbillo.generate_key_pair(E_start, a, b, P2, Q2, P3, Q3)
    print(f"[Sorbillo] {EA = }")
    print(f"[Sorbillo] {PA = }")
    print(f"[Sorbillo] {QA = }")

    EB, PB, QB = italiano.generate_key_pair(E_start, a, b, P2, Q2, P3, Q3)
    print(f"[Italiano] {EB = }")
    print(f"[Italiano] {PB = }")
    print(f"[Italiano] {QB = }")

    sorbillo.generate_shared_key(EB, PB, QB)
    italiano.generate_shared_key(EA, PA, QA)

    assert sorbillo.key == italiano.key

    print("Will you be able to order the special pizza?")
    while True:
        print("""
        1) Order a pizza
        2) Intercept an order
        """)
        option = input("> ")
        if option == '1':
            order_pizza()
        elif option == '2':
            intercepted_conversation(sorbillo, italiano)
        else:
            exit()

main()