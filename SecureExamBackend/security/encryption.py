import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_key():

    key = os.getenv("ENCRYPTION_KEY")

    if not key:
        raise Exception("ENCRYPTION_KEY is missing")

    key = base64.urlsafe_b64decode(key)

    if len(key) != 32:
        raise Exception("Key must be 32 bytes")

    return key


def encrypt_data(data):

    nonce = os.urandom(12)

    encrypted = AESGCM(get_key()).encrypt(
        nonce,
        data,
        None
    )

    return nonce + encrypted


def decrypt_data(data):

    nonce = data[:12]
    encrypted = data[12:]

    return AESGCM(get_key()).decrypt(
        nonce,
        encrypted,
        None
    )