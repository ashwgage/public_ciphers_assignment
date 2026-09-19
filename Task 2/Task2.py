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


def power(a, b, p):
    return pow(a, b, p)


# Attack 1:
# Mallory replaces Alice's and Bob's public values with q.
def public_key_attack():
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


    """ only things changed
    
    -mitm attack 
    
    """

    # Alice sends YA, but Mal swaps it for q before Bob receives it.
    # Bob sends YB, but Mal swaps it for q before Alice receives it.
    print("\n--- Mal ---")
    YB_alice_got = q  # Alice thinks this is Bob's public key
    YA_bob_got = q  # Bob thinks this is Alice's public key
    print("Mal sends q to Bob instead of YA")
    print("Mal sends q to Alice instead of YB")

    # Generating the shared secret key (from the TAMPERED values)
    K_Alice = power(YB_alice_got, XA, q)  # Alice's calculation of the shared secret
    K_Bob = power(YA_bob_got, XB, q)  # Bob's calculation of the shared secret

    # Mal does not need XA or XB. q mod q == 0, so q^anything mod q == 0.
    K_Mal = 0

    print(f"\nShared secret key calculated by Alice: {K_Alice}")
    print(f"Shared secret key calculated by Bob: {K_Bob}")
    print(f"Shared secret known by Mal: {K_Mal}")

    # ---

    if K_Alice != K_Bob:
        print("Key exchange failed: shared secrets don't match")
        return
    print("The shared secrets match")
    print(f"Mal guessed it correctly: {K_Mal == K_Alice}")

    # derive its own key from the shared secret
    k_alice = key_derive(K_Alice)
    k_bob = key_derive(K_Bob)
    k_mal = key_derive(K_Mal)  # Mal derives the same key

    print(f"\nAlice's AES key:   {k_alice.hex()}")
    print(f"Bob's AES key:     {k_bob.hex()}")
    print(f"Mal's AES key: {k_mal.hex()}")
    print(f"Keys match: {k_alice == k_bob == k_mal}")

    # Alice encrypts a message and Bob decrypts it
    msg_a = "yo this working? (key worked)"
    ct_a = encrypt(k_alice, msg_a)
    print("\n--- Alice -> Bob ---")
    print(f"Plaintext:      {msg_a}")
    print(f"Ciphertext c0:  {ct_a.hex()}")
    print(f"Bob reads:      {decrypt(k_bob, ct_a)}")
    print(f"MAL reads:  {decrypt(k_mal, ct_a)}")

    # Bob replies, Alice decrypts it
    msg_b = "it works (key worked)"
    ct_b = encrypt(k_bob, msg_b)
    print("\n--- Bob -> Alice ---")
    print(f"Plaintext:      {msg_b}")
    print(f"Ciphertext c1:  {ct_b.hex()}")
    print(f"Alice reads:    {decrypt(k_alice, ct_b)}")
    print(f"MAL reads:  {decrypt(k_mal, ct_b)}")

    # Mal can forge messages too, not just read them
    forged = encrypt(k_mal, "Hi Bob! Send Mal the report.")
    print("\n--- Mal forges a message to Bob ---")
    print(f"Bob reads: {decrypt(k_bob, forged)}")
    print("\nAlice and Bob noticed nothing wrong.")


# Attack 2:
# Mallory replaces the generator alpha with 1, q, or q - 1.
def generator_attack(malicious_alpha, alpha_name):

    print(f"\n--- Generator Attack: α = {alpha_name} ---")

    # Alice's private and public keys
    XA = 6
    YA = power(malicious_alpha, XA, q)
    print(f"Alice's private key XA: {XA}")
    print(f"Alice's public key YA: {YA}")

    # Bob's private and public keys
    XB = 15
    YB = power(malicious_alpha, XB, q)
    print(f"Bob's private key XB: {XB}")
    print(f"Bob's public key YB: {YB}")

    # Alice and Bob calculate the shared secret using
    # Mallory's manipulated generator.
    K_Alice = power(YB, XA, q)
    K_Bob = power(YA, XB, q)

    print(f"Shared secret key calculated by Alice: {K_Alice}")
    print(f"Shared secret key calculated by Bob: {K_Bob}")

    if K_Alice != K_Bob:
        print("Key exchange failed: shared secrets don't match")
        return

    print("The shared secrets match")

    # Mallory can determine the shared secret without
    # knowing Alice's or Bob's private keys.
    if malicious_alpha == 1:
        K_Mal = 1

    elif malicious_alpha == q:
        K_Mal = 0

    else:  # malicious_alpha == q - 1

        # If both public keys are q - 1, both private
        # exponents were odd, so the secret is q - 1.
        if YA == q - 1 and YB == q - 1:
            K_Mal = q - 1
        else:
            K_Mal = 1

    print(f"Shared secret known by Mal: {K_Mal}")
    print(f"Mal guessed it correctly: {K_Mal == K_Alice}")

    # Alice, Bob, and Mallory derive AES keys.
    k_alice = key_derive(K_Alice)
    k_bob = key_derive(K_Bob)
    k_mal = key_derive(K_Mal)

    print(f"\nAlice's AES key: {k_alice.hex()}")
    print(f"Bob's AES key:   {k_bob.hex()}")
    print(f"Mal's AES key:   {k_mal.hex()}")
    print(f"Keys match: {k_alice == k_bob == k_mal}")

    # Alice encrypts a message and Bob decrypts it.
    msg_a = "yo this working? (key worked)"
    ct_a = encrypt(k_alice, msg_a)

    print("\n--- Alice -> Bob ---")
    print(f"Ciphertext c0: {ct_a.hex()}")
    print(f"Bob reads:     {decrypt(k_bob, ct_a)}")
    print(f"Mal reads:     {decrypt(k_mal, ct_a)}")

    # Bob replies and Alice decrypts it.
    msg_b = "it works (key worked)"
    ct_b = encrypt(k_bob, msg_b)

    print("\n--- Bob -> Alice ---")
    print(f"Ciphertext c1: {ct_b.hex()}")
    print(f"Alice reads:   {decrypt(k_alice, ct_b)}")
    print(f"Mal reads:     {decrypt(k_mal, ct_b)}")


def main():

    print(f"The value of q: {q}")
    print(f"The legitimate value of alpha: {alpha}")

    public_key_attack()

    generator_attack(1, "1")
    generator_attack(q, "q")
    generator_attack(q - 1, "q - 1")


if __name__ == "__main__":
    main()