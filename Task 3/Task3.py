import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
from math import gcd



def mod_pow(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0: return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m)
    if g != 1: raise Exception('Modular inverse does not exist')
    else: return x % m


if __name__ == "__main__":
    # Given values
    p = 17
    q = 11
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 7
    d = mod_inverse(e, phi)

    print(f"p = {p} and q = {q}")
    print(f"n = {p} x {q} = {n}")
    print(f"ϕ({n}) = {p-1} x {q-1} = {phi}")
    print(f"Select e relatively prime to {phi} and e < {phi}; we choose e = {e}")
    print(f"d = {d} because {d} x {e} mod {phi} = {(d * e) % phi}")

    # Public and Private keys
    PU = (e, n)
    PR = (d, n)

    print(f"PU = {{{e}, {n}}}")
    print(f"PR = {{{d}, {n}}}")

    # Encryption
    M = 88  # plaintext
    C = mod_pow(M, e, n)
    print(f"\nSelect plaintext M = {M}")
    print(f"Ciphertext C = {M}^{e} mod {n} = {C}")

    # Decryption
    M_decrypted = mod_pow(C, d, n)
    print(f"Plaintext M = {C}^{d} mod {n} = {M_decrypted}")

    # Additional verification
    print(f"\nVerification:")
    print(f"e * d mod ϕ(n) = {e} * {d} mod {phi} = {(e * d) % phi}")