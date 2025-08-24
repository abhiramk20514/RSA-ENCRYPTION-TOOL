import random
from Crypto.Util import number  # PyCryptodome required
import json

# Generate large prime numbers (e.g., 1024-bit)
def generate_large_prime(bits=512):
    return number.getPrime(bits)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    return pow(a, -1, m)

def generate_keys(bits=512):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while q == p:
        q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return ((e, n), (d, n))

def encrypt(text, pub_key):
    e, n = pub_key
    return ' '.join([str(pow(ord(char), e, n)) for char in text])

def decrypt(cipher_text, priv_key):
    d, n = priv_key
    try:
        parts = [int(c) for c in cipher_text.split()]
        return ''.join([chr(pow(char, d, n)) for char in parts])
    except Exception:
        return "Decryption Failed"

# Save/Load Keys
def save_keys(pub_key, priv_key, path="rsa_keys.json"):
    data = {
        "public": {"e": pub_key[0], "n": pub_key[1]},
        "private": {"d": priv_key[0], "n": priv_key[1]}
    }
    with open(path, 'w') as f:
        json.dump(data, f)

def load_keys(path="rsa_keys.json"):
    with open(path, 'r') as f:
        data = json.load(f)
    pub = (data["public"]["e"], data["public"]["n"])
    priv = (data["private"]["d"], data["private"]["n"])
    return pub, priv
