import math

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    m0, x0, x1 = phi, 0, 1
    if phi == 1:
        return 0
    while e > 1:
        q = e // phi
        phi, e = e % phi, phi
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Ambos os números devem ser primos.")
    elif p == q:
        raise ValueError("p e q não podem ser iguais.")

    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi_n) != 1 or e >= phi_n:
        e = (e + 2) % phi_n
        if e < 2:
            e = 3

    d = mod_inverse(e, phi_n)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext_message):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext_message]

def decrypt(private_key, ciphertext):
    d, n = private_key
    return ''.join([chr(pow(c, d, n)) for c in ciphertext])
