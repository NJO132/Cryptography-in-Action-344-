

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from crypto.constants import AES_BLOCK_SIZE, BACKEND


def unpad_message(padded_text: bytes) -> bytes:
    """Remove PKCS7 padding from decrypted plaintext."""
    unpadder = PKCS7(AES_BLOCK_SIZE).unpadder()
    unpadded_data = unpadder.update(padded_text) + unpadder.finalize()
    return unpadded_data


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=BACKEND
    )
    
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    plaintext = unpad_message(padded_plaintext)
    return plaintext


def rsa_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:

    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
