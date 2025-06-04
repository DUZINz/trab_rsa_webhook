import math

# Verifica se um número é primo
def is_prime(num):
    if num < 2:
        return False
    # Testa divisores de 2 até raiz quadrada de num
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

# Calcula o Máximo Divisor Comum (MDC) usando algoritmo de Euclides
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Calcula o inverso multiplicativo modular de e módulo phi (usado para achar d)
# Usando o Algoritmo de Euclides Estendido
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

# Gera o par de chaves RSA (pública e privada) a partir de dois primos p e q
def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Ambos os números devem ser primos.")
    elif p == q:
        raise ValueError("p e q não podem ser iguais.")

    n = p * q  # módulo usado nas chaves
    phi_n = (p - 1) * (q - 1)  # totiente de Euler

    e = 65537  # valor padrão para o expoente público e
    # Garante que e seja coprimo com phi_n e menor que phi_n
    while gcd(e, phi_n) != 1 or e >= phi_n:
        e = (e + 2) % phi_n
        if e < 2:
            e = 3

    d = mod_inverse(e, phi_n)  # calcula o expoente privado d

    # Retorna tuplas representando as chaves: pública (e,n) e privada (d,n)
    return ((e, n), (d, n))

# Criptografa uma mensagem texto usando a chave pública
# Cada caractere é convertido para ASCII, elevado a e módulo n
def encrypt(public_key, plaintext_message):
    e, n = public_key
    encrypted_chars = [pow(ord(char), e, n) for char in plaintext_message]
    return encrypted_chars

# Descriptografa a lista de inteiros criptografados usando a chave privada
# Cada número é elevado a d módulo n e convertido de volta para caractere ASCII
def decrypt(private_key, ciphertext_message):
    d, n = private_key
    decrypted_chars = [chr(pow(char_code, d, n)) for char_code in ciphertext_message]
    return "".join(decrypted_chars)
