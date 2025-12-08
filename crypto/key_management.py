

from typing import Dict, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.constants import BACKEND


def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=BACKEND
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')


def load_public_key(pem_data: str) -> rsa.RSAPublicKey:

    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=BACKEND
    )


def load_private_key(pem_data: str) -> rsa.RSAPrivateKey:

    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=None,
        backend=BACKEND
    )


def generate_user_keys(crypto_manager=None) -> Dict[str, Dict[str, str]]:
private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()
    
    return {
        'alice': {
            'private_key': serialize_private_key(alice_private),
            'public_key': serialize_public_key(alice_public)
        },
        'bob': {
            'private_key': serialize_private_key(bob_private),
            'public_key': serialize_public_key(bob_public)
        }
    }
