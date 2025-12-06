"""
================================================================================
CRYPTO_UTILS.PY - Secure Messaging Cryptographic Operations
================================================================================
ICS344 Cryptography Project - Secure Messaging Application

This module implements all cryptographic operations for the secure messaging app:
- RSA-2048 Key Generation and Management
- AES-256-CBC Encryption/Decryption with PKCS#7 Padding
- Digital Signatures using RSA with SHA-256
- Secure Message Payload Construction

CRYPTOGRAPHIC PRIMITIVES USED:
-----------------------------
1. AES-256-CBC: Symmetric encryption for message confidentiality
   - 256-bit key provides 2^256 possible keys (quantum-resistant level)
   - CBC mode chains blocks, requiring an IV (Initialization Vector)
   
2. RSA-2048: Asymmetric encryption for key exchange and signatures
   - Based on the mathematical difficulty of factoring large primes
   - Public key encrypts, Private key decrypts (for key exchange)
   - Private key signs, Public key verifies (for authentication)
   
3. SHA-256: Cryptographic hash function for integrity
   - Produces 256-bit digest
   - Used in signature generation (sign the hash, not the message)

Author: ICS344 Project Team
================================================================================
"""

import os
import json
import time
import base64
from typing import Dict, Tuple, Optional, Any

# ============================================================================
# CRYPTOGRAPHY LIBRARY IMPORTS
# ============================================================================
# The pyca/cryptography library is the recommended modern Python crypto library
# It provides both high-level recipes and low-level primitives

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend


class CryptoManager:
    """
    ============================================================================
    CryptoManager Class
    ============================================================================
    
    This class encapsulates all cryptographic operations for the secure messaging
    application. It provides methods for:
    
    1. Key Generation (RSA-2048 key pairs)
    2. Symmetric Encryption (AES-256-CBC)
    3. Asymmetric Encryption (RSA for session key encryption)
    4. Digital Signatures (RSA-SHA256)
    5. Complete Send/Receive Workflows
    
    SECURITY PROPERTIES ACHIEVED:
    ----------------------------
    - CONFIDENTIALITY: AES-256-CBC encryption ensures only intended recipient
                       can read the message
    - INTEGRITY: SHA-256 hash in signature detects any message tampering
    - AUTHENTICATION: RSA signature proves sender's identity
    - NON-REPUDIATION: Sender cannot deny sending (signature proves origin)
    
    ============================================================================
    """
    
    # AES Block size is always 128 bits (16 bytes) regardless of key size
    AES_BLOCK_SIZE = 128  # bits (used for PKCS7 padding)
    AES_KEY_SIZE = 32     # bytes (256 bits for AES-256)
    IV_SIZE = 16          # bytes (128 bits, same as block size)
    
    def __init__(self):
        """
        Initialize the CryptoManager.
        
        The backend handles the actual cryptographic operations using
        OpenSSL or other system crypto libraries.
        """
        self.backend = default_backend()
    
    # ========================================================================
    # RSA KEY GENERATION
    # ========================================================================
    
    def generate_rsa_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA-2048 key pair for a user.
        
        RSA (Rivest-Shamir-Adleman) EXPLAINED:
        -------------------------------------
        RSA security is based on the computational difficulty of factoring
        the product of two large prime numbers.
        
        Key Generation Process:
        1. Choose two large random primes: p and q
        2. Compute n = p * q (this is the modulus)
        3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
        4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
           (commonly e = 65537 = 0x10001)
        5. Compute d such that d * e ≡ 1 (mod φ(n))
           (d is the modular multiplicative inverse of e)
        
        Public Key: (n, e)  - Can be shared with everyone
        Private Key: (n, d) - Must be kept secret
        
        WHY 2048 BITS?
        -------------
        - 2048-bit RSA provides approximately 112 bits of security
        - NIST recommends 2048-bit minimum for use through 2030
        - Factoring 2048-bit numbers is computationally infeasible
        
        Returns:
            Tuple of (private_key, public_key) objects
        """
        # Generate private key with public exponent 65537
        # 65537 (0x10001) is chosen because:
        # - It's prime (required for RSA)
        # - It has only two 1-bits in binary (fast exponentiation)
        # - It's large enough to prevent certain attacks
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard choice, 2^16 + 1
            key_size=2048,          # 2048 bits = 256 bytes
            backend=self.backend
        )
        
        # Extract public key from private key
        # The public key contains (n, e) from the private key
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def serialize_public_key(self, public_key: rsa.RSAPublicKey) -> str:
        """
        Serialize an RSA public key to PEM format for storage/transmission.
        
        PEM (Privacy Enhanced Mail) FORMAT:
        ----------------------------------
        PEM is a Base64-encoded format wrapped with header/footer lines:
        
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
        -----END PUBLIC KEY-----
        
        The internal format is SubjectPublicKeyInfo (SPKI) which contains:
        - Algorithm identifier (RSA)
        - The actual public key data (n and e)
        
        Args:
            public_key: RSA public key object
            
        Returns:
            PEM-encoded public key as string
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def serialize_private_key(self, private_key: rsa.RSAPrivateKey) -> str:
        """
        Serialize an RSA private key to PEM format.
        
        WARNING: Private keys must be stored securely!
        In production, use encryption (provide a password).
        
        Args:
            private_key: RSA private key object
            
        Returns:
            PEM-encoded private key as string
        """
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # No password for demo
        )
        return pem.decode('utf-8')
    
    def load_public_key(self, pem_data: str) -> rsa.RSAPublicKey:
        """
        Load an RSA public key from PEM format.
        
        Args:
            pem_data: PEM-encoded public key string
            
        Returns:
            RSA public key object
        """
        return serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=self.backend
        )
    
    def load_private_key(self, pem_data: str) -> rsa.RSAPrivateKey:
        """
        Load an RSA private key from PEM format.
        
        Args:
            pem_data: PEM-encoded private key string
            
        Returns:
            RSA private key object
        """
        return serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=None,  # No password for demo
            backend=self.backend
        )
    
    # ========================================================================
    # AES SYMMETRIC ENCRYPTION
    # ========================================================================
    
    def generate_session_key(self) -> bytes:
        """
        Generate a cryptographically secure random AES-256 session key.
        
        SESSION KEY CONCEPT:
        -------------------
        A session key is a temporary symmetric key used for one communication
        session. Using fresh session keys provides:
        
        1. FORWARD SECRECY: Compromising one session key doesn't reveal
           past or future communications
        2. PERFORMANCE: Symmetric encryption is ~1000x faster than asymmetric
        3. HYBRID ENCRYPTION: Best of both worlds - RSA secures the key,
           AES secures the bulk data
        
        WHY 32 BYTES (256 BITS)?
        -----------------------
        - AES-256 requires exactly 256 bits (32 bytes) for the key
        - Provides 256-bit security level
        - Considered quantum-resistant (Grover's algorithm reduces to 128-bit)
        
        Returns:
            32 bytes of cryptographically secure random data
        """
        # os.urandom() uses the operating system's CSPRNG:
        # - Linux: /dev/urandom (fed by hardware entropy)
        # - Windows: CryptGenRandom (uses system entropy)
        return os.urandom(self.AES_KEY_SIZE)
    
    def generate_iv(self) -> bytes:
        """
        Generate a cryptographically secure random Initialization Vector (IV).
        
        INITIALIZATION VECTOR (IV) EXPLAINED:
        ------------------------------------
        The IV is a random value used to ensure that encrypting the same
        plaintext twice produces different ciphertexts.
        
        CBC MODE REQUIRES:
        - A unique IV for each encryption operation
        - IV must be unpredictable (random)
        - IV does NOT need to be secret (transmitted alongside ciphertext)
        - IV size = AES block size = 128 bits = 16 bytes
        
        WHY IS IV IMPORTANT?
        -------------------
        Without IV, identical plaintexts would produce identical ciphertexts,
        leaking information about message patterns (violates semantic security).
        
        Example without IV:
            Encrypt("ATTACK AT DAWN") -> 0xABCD...
            Encrypt("ATTACK AT DAWN") -> 0xABCD... (same!)
        
        With random IV:
            Encrypt("ATTACK AT DAWN", IV1) -> 0xABCD...
            Encrypt("ATTACK AT DAWN", IV2) -> 0x1234... (different!)
        
        Returns:
            16 bytes of cryptographically secure random data
        """
        return os.urandom(self.IV_SIZE)
    
    def pad_message(self, plaintext: bytes) -> bytes:
        """
        Apply PKCS#7 padding to the plaintext.
        
        PKCS#7 PADDING EXPLAINED:
        ------------------------
        Block ciphers like AES operate on fixed-size blocks (128 bits for AES).
        If the plaintext isn't a multiple of the block size, we must pad it.
        
        PKCS#7 ALGORITHM:
        1. Calculate bytes needed: pad_len = block_size - (len(data) % block_size)
        2. Append pad_len bytes, each with value pad_len
        
        EXAMPLES (16-byte blocks):
        - "HELLO" (5 bytes) -> "HELLO" + 11 bytes of 0x0B
        - "HELLO WORLD!!!!" (16 bytes) -> add 16 bytes of 0x10
        
        WHY PKCS#7?
        ----------
        - Unambiguous: We always know exactly how many bytes to remove
        - Self-describing: The padding value tells us its length
        - Works for any block size up to 255 bytes
        
        Args:
            plaintext: The raw message bytes
            
        Returns:
            Padded message (always a multiple of 16 bytes)
        """
        # Create a PKCS7 padder for 128-bit blocks
        padder = PKCS7(self.AES_BLOCK_SIZE).padder()
        
        # Pad the data
        padded_data = padder.update(plaintext) + padder.finalize()
        
        return padded_data
    
    def unpad_message(self, padded_text: bytes) -> bytes:
        """
        Remove PKCS#7 padding from decrypted data.
        
        UNPADDING PROCESS:
        -----------------
        1. Read the last byte - this is the pad length
        2. Verify all padding bytes have the correct value
        3. Remove the padding bytes
        
        SECURITY NOTE:
        -------------
        Improper unpadding can lead to PADDING ORACLE ATTACKS!
        Always use constant-time comparison for padding validation.
        The cryptography library handles this securely.
        
        Args:
            padded_text: The decrypted data with padding
            
        Returns:
            Original plaintext without padding
        """
        unpadder = PKCS7(self.AES_BLOCK_SIZE).unpadder()
        unpadded_data = unpadder.update(padded_text) + unpadder.finalize()
        return unpadded_data
    
    def aes_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Encrypt plaintext using AES-256 in CBC mode.
        
        AES (Advanced Encryption Standard) EXPLAINED:
        --------------------------------------------
        AES is a symmetric block cipher that encrypts 128-bit blocks.
        
        - Designed by Joan Daemen and Vincent Rijmen (Rijndael)
        - Selected by NIST in 2001 after a 5-year competition
        - Operates on a 4x4 matrix of bytes called the "state"
        
        AES ROUNDS (for AES-256):
        ------------------------
        AES-256 performs 14 rounds of transformations:
        1. AddRoundKey - XOR state with round key
        2. SubBytes - Non-linear byte substitution (S-box)
        3. ShiftRows - Cyclically shift rows
        4. MixColumns - Mix columns using Galois field math
        
        CBC (Cipher Block Chaining) MODE EXPLAINED:
        ------------------------------------------
        CBC chains blocks together for better security:
        
        Encryption:
        C[0] = E(K, P[0] XOR IV)      # First block XORs with IV
        C[i] = E(K, P[i] XOR C[i-1])  # Subsequent blocks XOR with previous ciphertext
        
        This means:
        - Identical plaintext blocks produce different ciphertext
        - A bit error in ciphertext corrupts current and next block
        - Encryption must be sequential (not parallelizable)
        
                    IV
                    |
                    v
        P[0] ---> XOR ---> AES(K) ---> C[0]
                                        |
                                        v
        P[1] ---> XOR ---> AES(K) ---> C[1]
                                        |
                                        v
        P[2] ---> XOR ---> AES(K) ---> C[2]
        
        Args:
            plaintext: Raw message (will be padded)
            key: 32-byte AES key
            iv: 16-byte initialization vector
            
        Returns:
            Encrypted ciphertext bytes
        """
        # Step 1: Pad the plaintext to a multiple of 16 bytes
        padded_plaintext = self.pad_message(plaintext)
        
        # Step 2: Create the AES-CBC cipher object
        # - algorithms.AES(key) creates the AES cipher with our key
        # - modes.CBC(iv) specifies CBC mode with our IV
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        # Step 3: Create an encryptor and encrypt the data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return ciphertext
    
    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256 in CBC mode.
        
        CBC DECRYPTION PROCESS:
        ----------------------
        Decryption is the reverse of encryption:
        
        P[0] = D(K, C[0]) XOR IV
        P[i] = D(K, C[i]) XOR C[i-1]
        
        Note: Decryption CAN be parallelized because each block only
        depends on the ciphertext (which we have entirely upfront).
        
        Args:
            ciphertext: Encrypted data
            key: 32-byte AES key (same key used for encryption)
            iv: 16-byte IV (same IV used for encryption)
            
        Returns:
            Decrypted plaintext (unpadded)
        """
        # Step 1: Create the AES-CBC cipher for decryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        # Step 2: Decrypt the ciphertext
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Step 3: Remove PKCS#7 padding
        plaintext = self.unpad_message(padded_plaintext)
        
        return plaintext
    
    # ========================================================================
    # RSA ASYMMETRIC ENCRYPTION (for Session Key)
    # ========================================================================
    
    def rsa_encrypt(self, data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypt data using RSA with OAEP padding.
        
        RSA ENCRYPTION MATH:
        -------------------
        Basic RSA: C = M^e mod n
        Where:
        - M = Message (as integer)
        - e = Public exponent
        - n = Modulus (product of two primes)
        - C = Ciphertext
        
        OAEP (Optimal Asymmetric Encryption Padding) EXPLAINED:
        ------------------------------------------------------
        Raw RSA (textbook RSA) is vulnerable to several attacks:
        - Deterministic: Same message always produces same ciphertext
        - Malleable: Attacker can manipulate ciphertext meaningfully
        
        OAEP provides:
        - Semantic security (randomized encryption)
        - Chosen-ciphertext attack resistance
        - Non-malleability
        
        OAEP Structure:
        1. Pad message with random data
        2. Use hash functions (MGF - Mask Generation Function)
        3. Produce randomized padded message
        4. Encrypt with RSA
        
        Args:
            data: Data to encrypt (must be small, e.g., session key)
            public_key: Recipient's RSA public key
            
        Returns:
            RSA-OAEP encrypted data
        """
        # OAEP padding with SHA-256 for both the hash and MGF
        ciphertext = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
                algorithm=hashes.SHA256(),  # Hash algorithm
                label=None  # Optional label (not used)
            )
        )
        return ciphertext
    
    def rsa_decrypt(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decrypt RSA-encrypted data.
        
        RSA DECRYPTION MATH:
        -------------------
        Basic RSA: M = C^d mod n
        Where:
        - C = Ciphertext
        - d = Private exponent
        - n = Modulus
        - M = Original message
        
        WHY THIS WORKS (Mathematical Proof):
        -----------------------------------
        From Euler's theorem: a^φ(n) ≡ 1 (mod n) for gcd(a,n)=1
        
        Since e*d ≡ 1 (mod φ(n)), we have e*d = 1 + k*φ(n) for some k
        
        C^d = (M^e)^d = M^(e*d) = M^(1 + k*φ(n)) = M * (M^φ(n))^k ≡ M * 1^k = M (mod n)
        
        Args:
            ciphertext: RSA-encrypted data
            private_key: Recipient's RSA private key
            
        Returns:
            Decrypted original data
        """
        plaintext = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    # ========================================================================
    # DIGITAL SIGNATURES
    # ========================================================================
    
    def sign_message(self, message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Create a digital signature for a message.
        
        DIGITAL SIGNATURE CONCEPT:
        -------------------------
        A digital signature provides:
        1. AUTHENTICATION: Proves who created the message
        2. INTEGRITY: Detects if message was modified
        3. NON-REPUDIATION: Sender cannot deny sending
        
        RSA SIGNATURE PROCESS:
        ---------------------
        1. Hash the message: H = SHA256(message)
        2. Sign the hash: S = H^d mod n (encrypt with PRIVATE key)
        
        Why hash first?
        - RSA can only sign data smaller than the key size
        - Hashing reduces any message to 256 bits
        - Hashing is much faster than RSA
        
        PSS (Probabilistic Signature Scheme) PADDING:
        --------------------------------------------
        Like OAEP for encryption, PSS adds security to signatures:
        - Randomized signatures (same message, different signatures)
        - Provably secure in the random oracle model
        - Maximum salt length for maximum security
        
        Args:
            message: The data to sign
            private_key: Signer's RSA private key
            
        Returns:
            Digital signature bytes
        """
        signature = private_key.sign(
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),  # Mask Generation Function
                salt_length=asym_padding.PSS.MAX_LENGTH  # Maximum randomness
            ),
            hashes.SHA256()  # Hash algorithm
        )
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes, 
                         public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify a digital signature.
        
        SIGNATURE VERIFICATION PROCESS:
        ------------------------------
        1. "Decrypt" signature with public key: H' = S^e mod n
        2. Hash the received message: H = SHA256(message)
        3. Compare H and H' (with PSS unpadding)
        
        If they match, the signature is valid, proving:
        - The message wasn't modified (integrity)
        - The holder of the private key signed it (authentication)
        
        Args:
            message: The received message
            signature: The signature to verify
            public_key: Signer's RSA public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            # Verification failed - signature is invalid
            return False
    
    # ========================================================================
    # COMPLETE SECURE MESSAGING WORKFLOWS
    # ========================================================================
    
    def create_secure_payload(self, plaintext: str, 
                               sender_private_key: rsa.RSAPrivateKey,
                               receiver_public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        """
        Create a complete secure message payload (SENDER'S WORKFLOW).
        
        HYBRID ENCRYPTION SCHEME:
        -------------------------
        This implements a hybrid encryption system that combines:
        - Asymmetric crypto (RSA) for secure key exchange
        - Symmetric crypto (AES) for efficient bulk encryption
        - Digital signatures for authentication and integrity
        
        COMPLETE WORKFLOW:
        -----------------
        
        ┌─────────────────────────────────────────────────────────────────┐
        │                     SENDER (Alice)                               │
        ├─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │  1. Generate Session Key (32 bytes) ────┐                       │
        │                                          │                       │
        │  2. Generate IV (16 bytes) ─────────────┼─┐                     │
        │                                          │ │                     │
        │  3. Plaintext ──► PKCS7 Pad ──► AES-CBC ─┘ │                    │
        │                                    │       │                     │
        │                                    ▼       │                     │
        │                              Ciphertext ───┼─────────────────┐  │
        │                                    │       │                 │  │
        │  4. Session Key ──► RSA Encrypt ──┼───────┼──────┐          │  │
        │     (with Bob's Public Key)       │       │      │          │  │
        │                                    │       │      │          │  │
        │  5. Ciphertext ──► SHA256 ──► RSA Sign ───┼──────┼────┐     │  │
        │     (with Alice's Private Key)    │       │      │    │     │  │
        │                                    │       │      │    │     │  │
        │  6. Add Timestamp ────────────────┼───────┼──────┼────┼──┐  │  │
        │                                    │       │      │    │  │  │  │
        │  ┌─────────────────────────────────┼───────┼──────┼────┼──┼──┼──┤
        │  │           FINAL PAYLOAD         │       │      │    │  │  │  │
        │  ├─────────────────────────────────┼───────┼──────┼────┼──┼──┼──┤
        │  │  encrypted_session_key ◄────────┼───────┼──────┘    │  │  │  │
        │  │  iv ◄───────────────────────────┼───────┘           │  │  │  │
        │  │  ciphertext ◄───────────────────┘                   │  │  │  │
        │  │  signature ◄────────────────────────────────────────┘  │  │  │
        │  │  timestamp ◄───────────────────────────────────────────┘  │  │
        │  └───────────────────────────────────────────────────────────┘  │
        │                                                                  │
        └─────────────────────────────────────────────────────────────────┘
        
        Args:
            plaintext: The message to send
            sender_private_key: Alice's private key (for signing)
            receiver_public_key: Bob's public key (for encrypting session key)
            
        Returns:
            Dictionary containing the complete encrypted payload with:
            - encrypted_session_key: Base64-encoded RSA-encrypted AES key
            - iv: Base64-encoded initialization vector
            - ciphertext: Base64-encoded AES-encrypted message
            - signature: Base64-encoded digital signature
            - timestamp: Unix timestamp for replay protection
        """
        logs = []  # Collect operation logs for the UI
        
        # ===== STEP 1: Generate Session Key =====
        # A fresh 256-bit key for this message only
        session_key = self.generate_session_key()
        logs.append(f"[STEP 1] Generated AES-256 Session Key: {session_key.hex()}")
        
        # ===== STEP 2: Generate IV =====
        # Random 128-bit value for CBC mode
        iv = self.generate_iv()
        logs.append(f"[STEP 2] Generated IV (16 bytes): {iv.hex()}")
        
        # ===== STEP 3: Encrypt Message with AES-CBC =====
        # Convert plaintext to bytes and encrypt
        plaintext_bytes = plaintext.encode('utf-8')
        logs.append(f"[STEP 3] Original Message: {plaintext}")
        logs.append(f"[STEP 3] Message as bytes: {plaintext_bytes.hex()}")
        
        ciphertext = self.aes_encrypt(plaintext_bytes, session_key, iv)
        logs.append(f"[STEP 3] AES-CBC Ciphertext: {ciphertext.hex()}")
        
        # ===== STEP 4: Encrypt Session Key with RSA =====
        # Only the intended recipient can decrypt this
        encrypted_session_key = self.rsa_encrypt(session_key, receiver_public_key)
        logs.append(f"[STEP 4] RSA-Encrypted Session Key: {encrypted_session_key.hex()[:64]}...")
        
        # ===== STEP 5: Sign the Ciphertext =====
        # Creates proof that Alice sent this exact ciphertext
        signature = self.sign_message(ciphertext, sender_private_key)
        logs.append(f"[STEP 5] RSA-SHA256 Signature: {signature.hex()[:64]}...")
        
        # ===== STEP 6: Add Timestamp =====
        # Used to detect replay attacks
        timestamp = time.time()
        logs.append(f"[STEP 6] Timestamp: {timestamp}")
        
        # ===== Construct Final Payload =====
        # Base64 encode binary data for JSON transmission
        payload = {
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8'),
            'timestamp': timestamp
        }
        
        logs.append(f"[COMPLETE] Payload ready for transmission")
        
        return {
            'payload': payload,
            'logs': logs,
            'session_key_hex': session_key.hex()  # For educational display only!
        }
    
    def process_received_payload(self, payload: Dict[str, Any],
                                  receiver_private_key: rsa.RSAPrivateKey,
                                  sender_public_key: rsa.RSAPublicKey,
                                  replay_window: int = 60,
                                  used_nonces: Optional[set] = None) -> Dict[str, Any]:
        """
        Process and decrypt a received secure message payload (RECEIVER'S WORKFLOW).
        
        RECEIVER WORKFLOW:
        -----------------
        
        ┌─────────────────────────────────────────────────────────────────┐
        │                     RECEIVER (Bob)                               │
        ├─────────────────────────────────────────────────────────────────┤
        │                                                                  │
        │  RECEIVED PAYLOAD                                                │
        │  ┌────────────────────────────────┐                             │
        │  │ encrypted_session_key          │                             │
        │  │ iv                             │                             │
        │  │ ciphertext                     │                             │
        │  │ signature                      │                             │
        │  │ timestamp                      │                             │
        │  └────────────────────────────────┘                             │
        │           │                                                      │
        │           ▼                                                      │
        │  ┌────────────────────────────────┐                             │
        │  │ STEP 1: Verify Signature       │                             │
        │  │ signature + ciphertext         │──► Alice's Public Key       │
        │  │ If invalid: REJECT (tampering) │                             │
        │  └────────────────────────────────┘                             │
        │           │                                                      │
        │           ▼                                                      │
        │  ┌────────────────────────────────┐                             │
        │  │ STEP 2: Check Timestamp        │                             │
        │  │ If > 60 seconds old: REJECT    │──► REPLAY ATTACK detected   │
        │  │ If nonce reused: REJECT        │                             │
        │  └────────────────────────────────┘                             │
        │           │                                                      │
        │           ▼                                                      │
        │  ┌────────────────────────────────┐                             │
        │  │ STEP 3: Decrypt Session Key    │                             │
        │  │ encrypted_session_key          │──► Bob's Private Key        │
        │  └────────────────────────────────┘                             │
        │           │                                                      │
        │           ▼                                                      │
        │  ┌────────────────────────────────┐                             │
        │  │ STEP 4: Decrypt Message        │                             │
        │  │ ciphertext + iv + session_key  │──► AES-CBC Decrypt          │
        │  │ Remove PKCS7 padding           │                             │
        │  └────────────────────────────────┘                             │
        │           │                                                      │
        │           ▼                                                      │
        │      PLAINTEXT MESSAGE                                           │
        │                                                                  │
        └─────────────────────────────────────────────────────────────────┘
        
        Args:
            payload: The received encrypted payload
            receiver_private_key: Bob's private key (for decrypting session key)
            sender_public_key: Alice's public key (for verifying signature)
            replay_window: Maximum age of message in seconds (default 60)
            used_nonces: Set of previously used timestamps (for replay detection)
            
        Returns:
            Dictionary containing:
            - success: Boolean indicating if decryption succeeded
            - plaintext: Decrypted message (if successful)
            - error: Error message (if failed)
            - logs: List of operation logs
        """
        logs = []
        
        try:
            # ===== Decode Base64 Data =====
            encrypted_session_key = base64.b64decode(payload['encrypted_session_key'])
            iv = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            signature = base64.b64decode(payload['signature'])
            timestamp = payload['timestamp']
            
            logs.append(f"[RECEIVED] Encrypted Session Key: {encrypted_session_key.hex()[:32]}...")
            logs.append(f"[RECEIVED] IV: {iv.hex()}")
            logs.append(f"[RECEIVED] Ciphertext: {ciphertext.hex()}")
            logs.append(f"[RECEIVED] Signature: {signature.hex()[:32]}...")
            logs.append(f"[RECEIVED] Timestamp: {timestamp}")
            
            # ===== STEP 1: Verify Signature =====
            # This proves the ciphertext wasn't tampered with and came from Alice
            logs.append("[STEP 1] Verifying signature with sender's public key...")
            
            if not self.verify_signature(ciphertext, signature, sender_public_key):
                logs.append("[STEP 1] ❌ SIGNATURE VERIFICATION FAILED!")
                logs.append("[SECURITY] Possible message tampering or wrong sender!")
                return {
                    'success': False,
                    'error': 'Signature verification failed - message may be tampered!',
                    'logs': logs,
                    'attack_detected': 'INTEGRITY_ATTACK'
                }
            
            logs.append("[STEP 1] ✓ Signature verified successfully")
            
            # ===== STEP 2: Check Timestamp (Replay Attack Defense) =====
            logs.append("[STEP 2] Checking timestamp for replay attack...")
            
            current_time = time.time()
            message_age = current_time - timestamp
            
            logs.append(f"[STEP 2] Message age: {message_age:.2f} seconds")
            logs.append(f"[STEP 2] Replay window: {replay_window} seconds")
            
            if message_age > replay_window:
                logs.append(f"[STEP 2] ❌ REPLAY ATTACK DETECTED!")
                logs.append(f"[SECURITY] Message is {message_age:.2f}s old (max {replay_window}s)")
                return {
                    'success': False,
                    'error': f'Replay attack detected! Message is {message_age:.2f}s old.',
                    'logs': logs,
                    'attack_detected': 'REPLAY_ATTACK'
                }
            
            # Check for nonce reuse (additional replay protection)
            if used_nonces is not None:
                nonce = f"{timestamp}_{ciphertext.hex()[:16]}"
                if nonce in used_nonces:
                    logs.append("[STEP 2] ❌ NONCE REUSE DETECTED!")
                    return {
                        'success': False,
                        'error': 'Replay attack detected! This exact message was already received.',
                        'logs': logs,
                        'attack_detected': 'REPLAY_ATTACK'
                    }
                used_nonces.add(nonce)
            
            logs.append("[STEP 2] ✓ Timestamp valid, not a replay")
            
            # ===== STEP 3: Decrypt Session Key =====
            logs.append("[STEP 3] Decrypting session key with receiver's private key...")
            
            session_key = self.rsa_decrypt(encrypted_session_key, receiver_private_key)
            logs.append(f"[STEP 3] Recovered Session Key: {session_key.hex()}")
            
            # ===== STEP 4: Decrypt Message =====
            logs.append("[STEP 4] Decrypting message with AES-CBC...")
            
            plaintext_bytes = self.aes_decrypt(ciphertext, session_key, iv)
            plaintext = plaintext_bytes.decode('utf-8')
            
            logs.append(f"[STEP 4] Decrypted bytes: {plaintext_bytes.hex()}")
            logs.append(f"[STEP 4] Decrypted message: {plaintext}")
            
            logs.append("[COMPLETE] ✓ Message successfully decrypted and verified!")
            
            return {
                'success': True,
                'plaintext': plaintext,
                'logs': logs,
                'session_key_hex': session_key.hex()
            }
            
        except Exception as e:
            logs.append(f"[ERROR] Decryption failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'logs': logs
            }


# ============================================================================
# ATTACK SIMULATION HELPERS
# ============================================================================

class AttackSimulator:
    """
    Simulates various cryptographic attacks for educational purposes.
    
    ATTACK CATEGORIES (CIA Triad + Authentication):
    ----------------------------------------------
    1. CONFIDENTIALITY ATTACKS: Aim to read secret data
       - Replay Attack: Resend captured messages
       
    2. INTEGRITY ATTACKS: Aim to modify data undetected
       - Message Injection: Insert fake messages
       
    3. AUTHENTICATION ATTACKS: Aim to impersonate users
       - Man-in-the-Middle: Intercept and modify communications
       
    4. AVAILABILITY ATTACKS: Aim to disrupt service
       - Denial of Service: Overwhelm the system with requests
    """
    
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto = crypto_manager
    
    def simulate_replay_attack(self, original_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        REPLAY ATTACK SIMULATION
        
        ATTACK DESCRIPTION:
        ------------------
        An attacker captures a legitimate encrypted message and resends it
        later, attempting to cause the action to be repeated.
        
        Real-world examples:
        - Replaying a "transfer $100" message to transfer multiple times
        - Replaying authentication tokens to gain repeated access
        
        DEFENSE:
        -------
        - Timestamps: Reject messages older than a threshold
        - Nonces: Unique identifiers that can only be used once
        - Sequence numbers: Messages must arrive in order
        
        This simulation returns the original payload unchanged,
        which should be rejected due to timestamp expiration.
        """
        # Simply return the same payload - it should be rejected
        # because the timestamp is now too old
        replayed_payload = original_payload.copy()
        
        return {
            'attack_type': 'REPLAY_ATTACK',
            'description': 'Attempting to resend a captured message',
            'payload': replayed_payload,
            'expected_result': 'Should be rejected due to expired timestamp'
        }
    
    def simulate_message_injection(self, 
                                    injected_message: str,
                                    receiver_public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        """
        MESSAGE INJECTION ATTACK SIMULATION
        
        ATTACK DESCRIPTION:
        ------------------
        The attacker (Mallory) crafts their OWN message and tries to send it
        to the victim (Bob) while impersonating the legitimate sender (Alice).
        
        KEY INSIGHT: The attacker does NOT have Alice's private key!
        
        ATTACK STEPS:
        1. Mallory writes a malicious message
        2. Mallory encrypts it with Bob's public key (publicly available)
        3. Mallory tries to sign it - but without Alice's private key,
           they must use their own key or create a random signature
        4. Bob verifies the signature with Alice's public key - FAILS!
        
        DEFENSE:
        -------
        - Digital signatures provide AUTHENTICATION
        - Without Alice's private key, no valid signature can be created
        - Bob can verify the sender's identity using Alice's public key
        
        This differs from a modification attack (bit-flipping) because:
        - The attacker creates an entirely NEW message
        - The attacker properly encrypts the message
        - The attack fails because of AUTHENTICATION, not integrity
        """
        # Step 1: Attacker generates their own key pair
        attacker_private, attacker_public = self.crypto.generate_rsa_keypair()
        
        # Step 2: Attacker creates the malicious message
        session_key = self.crypto.generate_session_key()
        iv = self.crypto.generate_iv()
        
        # Step 3: Encrypt the injected message (attacker CAN do this with public key)
        plaintext_bytes = injected_message.encode('utf-8')
        ciphertext = self.crypto.aes_encrypt(plaintext_bytes, session_key, iv)
        encrypted_session_key = self.crypto.rsa_encrypt(session_key, receiver_public_key)
        
        # Step 4: Sign with ATTACKER's private key (NOT Alice's!)
        fake_signature = self.crypto.sign_message(ciphertext, attacker_private)
        
        # Step 5: Construct the forged payload
        forged_payload = {
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'signature': base64.b64encode(fake_signature).decode('utf-8'),
            'timestamp': time.time()
        }
        
        return {
            'attack_type': 'MESSAGE_INJECTION',
            'description': (
                f'Attacker crafted fake message: "{injected_message}" '
                'Encrypted properly but signed with WRONG key (attacker\'s key, not Alice\'s)'
            ),
            'payload': forged_payload,
            'attacker_public_key': self.crypto.serialize_public_key(attacker_public),
            'expected_result': 'Should be rejected - signature won\'t verify with Alice\'s public key'
        }
    
    def simulate_mitm_attack(self, 
                             original_sender_public_key: rsa.RSAPublicKey,
                             original_receiver_public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        """
        MAN-IN-THE-MIDDLE (MITM) ATTACK SIMULATION
        
        ATTACK DESCRIPTION:
        ------------------
        An attacker intercepts the public key exchange and substitutes
        their own public key. This allows them to:
        1. Decrypt messages intended for the real recipient
        2. Re-encrypt with the real recipient's key
        3. Read all communications while appearing legitimate
        
        ATTACK DIAGRAM:
        
        Alice ──────┐                    ┌────── Bob
                    │                    │
                    ▼                    ▼
        "Bob's Key" │                    │ "Alice's Key"
        (actually   │                    │ (actually
         Mallory's) │                    │  Mallory's)
                    │                    │
                    └────► MALLORY ◄─────┘
                           (Attacker)
        
        DEFENSE:
        -------
        - Certificate Authorities (CAs) sign public keys
        - Key fingerprint verification out-of-band
        - Trust on First Use (TOFU) with pinning
        
        This simulation generates an attacker's key pair that could be
        substituted in a public key directory.
        """
        # Generate attacker's key pair
        attacker_private_key, attacker_public_key = self.crypto.generate_rsa_keypair()
        
        return {
            'attack_type': 'MITM_ATTACK',
            'description': 'Attacker substitutes their public key in the directory',
            'attacker_public_key': self.crypto.serialize_public_key(attacker_public_key),
            'attacker_private_key': self.crypto.serialize_private_key(attacker_private_key),
            'original_sender_key': self.crypto.serialize_public_key(original_sender_public_key),
            'original_receiver_key': self.crypto.serialize_public_key(original_receiver_public_key),
            'expected_result': 'Messages encrypted with attacker key can be decrypted by attacker'
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def bytes_to_hex_display(data: bytes, max_length: int = 32) -> str:
    """Format bytes as hex string for display, truncating if needed."""
    hex_str = data.hex()
    if len(hex_str) > max_length * 2:
        return f"{hex_str[:max_length]}...({len(data)} bytes total)"
    return hex_str


def generate_user_keys(crypto_manager: CryptoManager) -> Dict[str, Dict[str, str]]:
    """
    Generate RSA key pairs for Alice and Bob.
    
    Returns a dictionary with serialized keys for both users.
    """
    # Generate Alice's keys
    alice_private, alice_public = crypto_manager.generate_rsa_keypair()
    
    # Generate Bob's keys
    bob_private, bob_public = crypto_manager.generate_rsa_keypair()
    
    return {
        'alice': {
            'private_key': crypto_manager.serialize_private_key(alice_private),
            'public_key': crypto_manager.serialize_public_key(alice_public)
        },
        'bob': {
            'private_key': crypto_manager.serialize_private_key(bob_private),
            'public_key': crypto_manager.serialize_public_key(bob_public)
        }
    }


# ============================================================================
# TEST / DEMO CODE
# ============================================================================

if __name__ == "__main__":
    """
    Demonstration of the cryptographic operations.
    Run this file directly to see the complete workflow.
    """
    print("=" * 70)
    print("SECURE MESSAGING CRYPTOGRAPHY DEMONSTRATION")
    print("=" * 70)
    
    # Initialize crypto manager
    crypto = CryptoManager()
    
    # Generate keys for Alice and Bob
    print("\n[1] Generating RSA-2048 key pairs...")
    alice_private, alice_public = crypto.generate_rsa_keypair()
    bob_private, bob_public = crypto.generate_rsa_keypair()
    print("    ✓ Alice's keys generated")
    print("    ✓ Bob's keys generated")
    
    # Alice sends a message to Bob
    print("\n[2] Alice sending message to Bob...")
    message = "Hello Bob! This is a secret message from Alice."
    
    result = crypto.create_secure_payload(
        plaintext=message,
        sender_private_key=alice_private,
        receiver_public_key=bob_public
    )
    
    print("\n    SENDER LOGS:")
    for log in result['logs']:
        print(f"    {log}")
    
    # Bob receives and decrypts the message
    print("\n[3] Bob receiving and decrypting...")
    
    received = crypto.process_received_payload(
        payload=result['payload'],
        receiver_private_key=bob_private,
        sender_public_key=alice_public
    )
    
    print("\n    RECEIVER LOGS:")
    for log in received['logs']:
        print(f"    {log}")
    
    if received['success']:
        print(f"\n    ✓ DECRYPTED MESSAGE: {received['plaintext']}")
    else:
        print(f"\n    ✗ DECRYPTION FAILED: {received['error']}")
    
    print("\n" + "=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)

