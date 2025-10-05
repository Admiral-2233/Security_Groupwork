# crypto_socp.py - RSA-4096 OAEP(SHA-256) + RSASSA-PSS(SHA-256)
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from common import b64url_encode, b64url_decode

RSA_BITS = 4096
HASH_LEN = 32
OAEP_MAX = (RSA_BITS // 8) - 2*HASH_LEN - 2  # MUST (k - 2*hLen - 2)

def gen_rsa4096_pair():
    key = RSA.generate(RSA_BITS)
    return key, key.publickey()

def export_pub_b64url(pub: RSA.RsaKey) -> str:
    return b64url_encode(pub.export_key(format="DER"))

def import_pub_b64url(s: str) -> RSA.RsaKey:
    return RSA.import_key(b64url_decode(s))

def export_priv_pem(priv: RSA.RsaKey) -> bytes:
    # 教学版：PEM 不加密；生产应使用密码派生密钥加密私钥  :contentReference[oaicite:14]{index=14}
    return priv.export_key(format="PEM", pkcs=8, protection=None)

def import_priv_pem(pem: bytes) -> RSA.RsaKey:
    return RSA.import_key(pem)

def rsa_oaep_encrypt(pub: RSA.RsaKey, data: bytes) -> bytes:
    return PKCS1_OAEP.new(pub, hashAlgo=SHA256).encrypt(data)

def rsa_oaep_decrypt(priv: RSA.RsaKey, ct: bytes) -> bytes:
    return PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(ct)

def sign_pss(priv: RSA.RsaKey, msg: bytes) -> bytes:
    h = SHA256.new(msg)
    return pss.new(priv).sign(h)

def verify_pss(pub: RSA.RsaKey, msg: bytes, sig: bytes) -> bool:
    h = SHA256.new(msg)
    try:
        pss.new(pub).verify(h, sig)
        return True
    except (ValueError, TypeError):
        return False
