

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from crypto.constants import AES_BLOCK_SIZE, AES_KEY_SIZE, IV_SIZE, BACKEND


def generate_session_key() -> bytes:

    return os.urandom(AES_KEY_SIZE)


def generate_iv() -> bytes:
  
    return os.urandom(IV_SIZE)


def pad_message(plaintext: bytes) -> bytes:

    padder = PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return padded_data


def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
   
    padded_plaintext = pad_message(plaintext)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=BACKEND
    )
    
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext


def rsa_encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:

    ciphertext = public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext
