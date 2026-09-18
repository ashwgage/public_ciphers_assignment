import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Public parameters
q = 37  # Prime number
alpha = 5  # Primitive root of q

#iv key gen
key_iv = bytes(range(16))


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


def power(a, b, p):
    return pow(a, b, p)

def main():

    print(f"The value of q: {q}")
    print(f"The value of α: {alpha}")

    # Alice's private and public keys
    XA = 6  # Alice's private key
    YA = power(alpha, XA, q)
    print(f"Alice's private key XA: {XA}")
    print(f"Alice's public key YA: {YA}")

    # Bob's private and public keys
    XB = 15  # Bob's private key
    YB = power(alpha, XB, q)
    print(f"Bob's private key XB: {XB}")
    print(f"Bob's public key YB: {YB}")

    # Generating the shared secret key
    K_Alice = power(YB, XA, q)  # Alice's calculation of the shared secret
    K_Bob = power(YA, XB, q)  # Bob's calculation of the shared secret

    print(f"Shared secret key calculated by Alice: {K_Alice}")
    print(f"Shared secret key calculated by Bob: {K_Bob}")

    # new checks:

    if K_Alice != K_Bob:
        print("Key exchange failed: shared secrets don't match")
        return
    print("The shared secrets match")

    # derive its own key from the shared secret
    k_alice = key_derive(K_Alice)
    k_bob = key_derive(K_Bob)

    print(f"\nAlice's AES key: {k_alice.hex()}")
    print(f"Bob's AES key:   {k_bob.hex()}")
    print(f"Keys match: {k_alice == k_bob}")


    # Alice encrypts a message and Bob decrypts it
    msg_a = "yo this working? (key worked)"
    ct_a = encrypt(k_alice, msg_a)
    print("\n--- Alice -> Bob ---")
    print(f"Plaintext:  {msg_a}")
    print(f"Ciphertext: {ct_a.hex()}")
    print(f"Bob reads:  {decrypt(k_bob, ct_a)}")

    # Bob replies, Alice decrypts it
    msg_b = "it works (key worked)"
    ct_b = encrypt(k_bob, msg_b)
    print("\n--- Bob -> Alice ---")
    print(f"Plaintext:   {msg_b}")
    print(f"Ciphertext:  {ct_b.hex()}")
    print(f"Alice reads: {decrypt(k_alice, ct_b)}")

if __name__ == "__main__":
    main()