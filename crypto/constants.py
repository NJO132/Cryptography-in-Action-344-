
from cryptography.hazmat.backends import default_backend

# AES Configuration
AES_BLOCK_SIZE = 128  # bits (used for PKCS7 padding)
AES_KEY_SIZE = 32     # bytes (256 bits for AES-256)
IV_SIZE = 16          # bytes (128 bits, same as block size)

# Replay Attack Prevention
REPLAY_WINDOW = 60    # seconds

# Cryptography Backend
BACKEND = default_backend()
