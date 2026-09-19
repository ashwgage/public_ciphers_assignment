import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad
from math import gcd


#iv key gen
block_size = 16 #aes block size
key_size = 16 #aes key size

def gen_key():
    return get_random_bytes(key_size)


def gen_iv():
    return get_random_bytes(block_size)

key_iv = gen_iv()

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, key_iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))


def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, key_iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()


def key_derive(key):
    key_bytes = str(key).encode() # turns key into a str and encodes it 5 -> "5" and encodes it
    return hashlib.sha256(key_bytes).digest()[:16]
        # hash with sha256 (.digest is feeding the bytes) and :16 is only keeping the first 16 bytes


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

    # RSA key generation
    # Change this to any desired prime size up to 2048 bits.
    prime_bits = 1024
    e = 65537

    print("--- RSA Key Generation ---")
    print(f"Generating two {prime_bits}-bit primes...")

    # Generate p and q until e is relatively prime to phi.
    while True:
        p = getPrime(prime_bits)
        q = getPrime(prime_bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) == 1:
            break

    # Calculate the private exponent d.
    d = mod_inverse(e, phi)

    print("RSA keys generated")
    print(f"n has {n.bit_length()} bits")
    print(f"Public exponent e = {e}")
    print(f"e * d mod ϕ(n) = {(e * d) % phi}")

    # Public and private keys
    PU = (e, n)
    PR = (d, n)

    print("\n--- Textbook RSA Encryption and Decryption ---")

    # Encryption
    M = 88
    C = mod_pow(M, e, n)

    print(f"Select plaintext M = {M}")
    print(f"Ciphertext C = {M}^{e} mod n = {C}")

    # Decryption
    M_decrypted = mod_pow(C, d, n)

    print(f"Decrypted plaintext M = {C}^{d} mod n = {M_decrypted}")
    print(f"Message matches: {M == M_decrypted}")

    # -------------------------------------------------
    # RSA malleability / MITM attack
    # -------------------------------------------------
    print("\n--- RSA Malleability Attack ---")

    # Bob chooses a random secret and encrypts it
    # using Alice's public key.
    while True:
        random_bytes = get_random_bytes((n.bit_length() + 7) // 8)
        s_bob = int.from_bytes(random_bytes, "big")

        if 1 < s_bob < n and gcd(s_bob, n) == 1:
            break

    c = mod_pow(s_bob, e, n)

    print(f"Bob's random secret s: {s_bob}")
    print(f"Bob sends ciphertext c: {c}")

    # Mal replaces c with c' = 1.
    # Alice will decrypt this to s = 1.
    c_prime = 1

    print(f"Mal changes c to c': {c_prime}")

    # Alice decrypts the ciphertext sent by Mal.
    s_alice = mod_pow(c_prime, d, n)
    k_alice = key_derive(s_alice)

    print(f"Alice decrypts c' and gets s: {s_alice}")

    # Alice encrypts a message using the compromised AES key.
    msg_a = "Hi Bob!"
    c0 = encrypt(k_alice, msg_a)

    print(f"Alice encrypts message: {msg_a}")
    print(f"Alice sends c0: {c0.hex()}")

    # Mal knows Alice's secret is 1, so Mal derives
    # the same AES key and decrypts the message.
    s_mal = 1
    k_mal = key_derive(s_mal)

    print(f"Mal knows the secret is: {s_mal}")
    print(f"Mal reads c0: {decrypt(k_mal, c0)}")

    # -------------------------------------------------
    # RSA signature malleability attack
    # -------------------------------------------------
    print("\n--- RSA Signature Malleability Attack ---")

    # Alice signs two messages.
    m1 = 7
    m2 = 11

    signature_1 = mod_pow(m1, d, n)
    signature_2 = mod_pow(m2, d, n)

    print(f"Message m1: {m1}")
    print(f"Signature for m1: {signature_1}")

    print(f"\nMessage m2: {m2}")
    print(f"Signature for m2: {signature_2}")

    # Mal multiplies two valid signatures to create
    # a valid signature for m3 = m1 * m2.
    m3 = (m1 * m2) % n
    signature_3 = (signature_1 * signature_2) % n

    print(f"\nForged message m3 = m1 * m2: {m3}")
    print(f"Forged signature for m3: {signature_3}")

    # Verify Mal's forged signature using the public key.
    verified_message = mod_pow(signature_3, e, n)

    print(f"Verification result: {verified_message}")
    print(f"Forged signature is valid: {verified_message == m3}")
