# crypto.py
# Handles encryption/decryption and key management for the chat system.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# RSA Key Generation
# create a new RSA key pair (private & public).
def generate_rsa_keypair():
    # Using 2048-bit RSA for security. This will be used to exchange AES keys.
    key = RSA.generate(2048)
    private_key = key      # RSA object for private key (contains d)
    public_key = key.publickey()  # RSA object for public key (contains e, n)
    return private_key, public_key

# RSA Encryption
# encrypt a message (bytes) with a given RSA public key.
def rsa_encrypt(pub_key, plaintext_bytes):
    # Using OAEP padding for RSA which is more secure than raw RSA.
    rsa_cipher = PKCS1_OAEP.new(pub_key)
    ciphertext = rsa_cipher.encrypt(plaintext_bytes)
    return ciphertext

# RSA Decryption
# decrypt a ciphertext (bytes) with our RSA private key.
def rsa_decrypt(priv_key, ciphertext_bytes):
    rsa_cipher = PKCS1_OAEP.new(priv_key)
    plaintext = rsa_cipher.decrypt(ciphertext_bytes)
    return plaintext

# AES Setup
# generate a random 256-bit AES key for a session.
def generate_aes_key():
    return get_random_bytes(32)  # 32 bytes = 256-bit key

# AES Encryption
# encrypt plaintext (str) with AES (CBC mode) using the given key.
def aes_encrypt(key, plaintext):
    # Convert plaintext string to bytes
    data = plaintext.encode('utf-8')
    iv = get_random_bytes(16)  # 128-bit IV for CBC mode
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)  # Using CFB mode for simplicity (no padding needed)
    ciphertext = cipher.encrypt(data)
    # Prepend IV to ciphertext for use in decryption. Encode to base64 for safe transmission as text.
    encrypted_bytes = iv + ciphertext
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_b64

# AES Decryption: decrypt a base64-encoded ciphertext string with AES key.
def aes_decrypt(key, b64_ciphertext):
    encrypted_bytes = base64.b64decode(b64_ciphertext.encode('utf-8'))
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    plaintext_bytes = cipher.decrypt(ciphertext)
    try:
        return plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # If bytes are not UTF-8 text (e.g., binary file data), return raw bytes
        return plaintext_bytes

# Digital signature (optional): In a full implementation, we might also include functions
# to sign messages with RSA private key and verify with public key for authenticity.
