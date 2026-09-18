import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# Public parameters
q_hex = """B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371"""

alpha_hex = """A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5"""  # Primitive root of q


def parse(text):
    return int("".join(text.split()), 16)

q = parse(q_hex)
alpha = parse(alpha_hex)

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