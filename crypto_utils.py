"""
Cryptographic Utilities Module
Implements AES-CBC encryption with PKCS#7 padding and RSA Digital Signatures
"""

import os
import base64
import hashlib
import time
import json
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ==================== AES-CBC Encryption ====================

class AESCipher:
    """AES-CBC encryption with PKCS#7 padding"""
    
    def __init__(self, key: bytes = None):
        """Initialize with 256-bit key (32 bytes)"""
        self.key = key if key else get_random_bytes(32)
        self.block_size = AES.block_size  # 16 bytes
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypt plaintext using AES-CBC with PKCS#7 padding
        Returns: dict with iv and ciphertext (base64 encoded)
        """
        # Generate random IV (16 bytes for AES)
        iv = get_random_bytes(self.block_size)
        
        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad plaintext to block size using PKCS#7
        plaintext_bytes = plaintext.encode('utf-8')
        padded_data = pad(plaintext_bytes, self.block_size)
        
        # Encrypt
        ciphertext = cipher.encrypt(padded_data)
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    def decrypt(self, iv_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt ciphertext using AES-CBC with PKCS#7 padding
        Returns: decrypted plaintext string
        """
        # Decode from base64
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, self.block_size)
        
        return decrypted.decode('utf-8')
    
    def get_key_b64(self) -> str:
        """Return base64 encoded key"""
        return base64.b64encode(self.key).decode('utf-8')
    
    @staticmethod
    def from_key_b64(key_b64: str) -> 'AESCipher':
        """Create AESCipher from base64 encoded key"""
        key = base64.b64decode(key_b64)
        return AESCipher(key)


# ==================== RSA Key Management ====================

class RSAKeyManager:
    """RSA key pair generation and management"""
    
    def __init__(self, key_size: int = 2048):
        """Generate new RSA key pair"""
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self) -> dict:
        """Generate new RSA key pair"""
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        
        return {
            'private_key': self.private_key.export_key().decode('utf-8'),
            'public_key': self.public_key.export_key().decode('utf-8')
        }
    
    def load_private_key(self, pem_key: str):
        """Load private key from PEM string"""
        self.private_key = RSA.import_key(pem_key)
        self.public_key = self.private_key.publickey()
    
    def load_public_key(self, pem_key: str):
        """Load public key from PEM string"""
        self.public_key = RSA.import_key(pem_key)
    
    def encrypt_aes_key(self, aes_key: bytes, recipient_public_key: str) -> str:
        """Encrypt AES session key with recipient's RSA public key"""
        from Crypto.Cipher import PKCS1_OAEP
        recipient_key = RSA.import_key(recipient_public_key)
        cipher = PKCS1_OAEP.new(recipient_key)
        encrypted_key = cipher.encrypt(aes_key)
        return base64.b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_aes_key(self, encrypted_key_b64: str) -> bytes:
        """Decrypt AES session key with our private key"""
        from Crypto.Cipher import PKCS1_OAEP
        encrypted_key = base64.b64decode(encrypted_key_b64)
        cipher = PKCS1_OAEP.new(self.private_key)
        return cipher.decrypt(encrypted_key)


# ==================== RSA Digital Signatures ====================

class RSASignature:
    """RSA Digital Signature operations using SHA-256"""
    
    @staticmethod
    def sign(message: str, private_key_pem: str) -> str:
        """
        Sign a message using RSA private key
        Returns: base64 encoded signature
        """
        private_key = RSA.import_key(private_key_pem)
        
        # Create hash of the message
        message_hash = SHA256.new(message.encode('utf-8'))
        
        # Sign the hash
        signature = pkcs1_15.new(private_key).sign(message_hash)
        
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify(message: str, signature_b64: str, public_key_pem: str) -> bool:
        """
        Verify a signature using RSA public key
        Returns: True if valid, False otherwise
        """
        try:
            public_key = RSA.import_key(public_key_pem)
            signature = base64.b64decode(signature_b64)
            
            # Create hash of the message
            message_hash = SHA256.new(message.encode('utf-8'))
            
            # Verify signature
            pkcs1_15.new(public_key).verify(message_hash, signature)
            return True
        except (ValueError, TypeError):
            return False


# ==================== Secure Message Protocol ====================

class SecureMessage:
    """
    Complete secure message protocol combining:
    - AES-CBC encryption for confidentiality
    - RSA for key exchange
    - RSA digital signatures for integrity/authentication
    - Nonce/timestamp for replay protection
    """
    
    def __init__(self):
        self.used_nonces = set()  # Track used nonces for replay protection
        self.nonce_timeout = 300  # 5 minutes timeout for nonces
    
    def create_secure_message(self, plaintext: str, sender_private_key: str, 
                              recipient_public_key: str) -> dict:
        """
        Create a secure message with encryption and signature
        
        Returns: Complete message package with:
        - encrypted_aes_key: RSA encrypted AES session key
        - iv: Initialization vector
        - ciphertext: AES encrypted message
        - signature: RSA signature of the payload
        - nonce: Unique identifier for replay protection
        - timestamp: Message creation time
        """
        # Generate session key and encrypt message
        aes = AESCipher()
        encrypted_data = aes.encrypt(plaintext)
        
        # Encrypt AES key with recipient's public key
        rsa_manager = RSAKeyManager()
        encrypted_aes_key = rsa_manager.encrypt_aes_key(aes.key, recipient_public_key)
        
        # Generate nonce and timestamp for replay protection
        nonce = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        timestamp = int(time.time())
        
        # Create payload to sign (ciphertext + nonce + timestamp)
        payload = json.dumps({
            'ciphertext': encrypted_data['ciphertext'],
            'iv': encrypted_data['iv'],
            'nonce': nonce,
            'timestamp': timestamp
        }, sort_keys=True)
        
        # Sign the payload
        signature = RSASignature.sign(payload, sender_private_key)
        
        return {
            'encrypted_aes_key': encrypted_aes_key,
            'iv': encrypted_data['iv'],
            'ciphertext': encrypted_data['ciphertext'],
            'signature': signature,
            'nonce': nonce,
            'timestamp': timestamp,
            'payload': payload  # Include for verification
        }
    
    def verify_and_decrypt(self, message: dict, sender_public_key: str,
                           recipient_private_key: str) -> dict:
        """
        Verify signature and decrypt secure message
        
        Returns: dict with status, plaintext (if successful), and security info
        """
        result = {
            'success': False,
            'plaintext': None,
            'security_checks': {
                'signature_valid': False,
                'replay_check_passed': False,
                'timestamp_valid': False,
                'integrity_intact': True
            },
            'warnings': [],
            'errors': []
        }
        
        try:
            # Reconstruct payload for verification
            payload = json.dumps({
                'ciphertext': message['ciphertext'],
                'iv': message['iv'],
                'nonce': message['nonce'],
                'timestamp': message['timestamp']
            }, sort_keys=True)
            
            # 1. Verify signature
            signature_valid = RSASignature.verify(
                payload, 
                message['signature'], 
                sender_public_key
            )
            result['security_checks']['signature_valid'] = signature_valid
            
            if not signature_valid:
                result['errors'].append("SIGNATURE VERIFICATION FAILED - Message may be tampered or from unauthorized sender!")
                return result
            
            # 2. Check replay attack (nonce)
            nonce = message['nonce']
            if nonce in self.used_nonces:
                result['security_checks']['replay_check_passed'] = False
                result['errors'].append("REPLAY ATTACK DETECTED - This message has been seen before!")
                return result
            result['security_checks']['replay_check_passed'] = True
            self.used_nonces.add(nonce)
            
            # 3. Check timestamp (prevent old messages)
            current_time = int(time.time())
            message_time = message['timestamp']
            time_diff = abs(current_time - message_time)
            
            if time_diff > self.nonce_timeout:
                result['security_checks']['timestamp_valid'] = False
                result['warnings'].append(f"Message is {time_diff} seconds old (threshold: {self.nonce_timeout}s)")
            else:
                result['security_checks']['timestamp_valid'] = True
            
            # 4. Decrypt AES key using recipient's private key
            rsa_manager = RSAKeyManager()
            rsa_manager.load_private_key(recipient_private_key)
            aes_key = rsa_manager.decrypt_aes_key(message['encrypted_aes_key'])
            
            # 5. Decrypt message
            aes = AESCipher(aes_key)
            plaintext = aes.decrypt(message['iv'], message['ciphertext'])
            
            result['success'] = True
            result['plaintext'] = plaintext
            
        except Exception as e:
            result['errors'].append(f"Decryption failed: {str(e)}")
            result['security_checks']['integrity_intact'] = False
        
        return result
    
    def clear_old_nonces(self):
        """Clear old nonces (would be done periodically in production)"""
        self.used_nonces.clear()


# ==================== Attack Simulation Module ====================

class AttackSimulator:
    """Simulate various attacks on the secure messaging system"""
    
    @staticmethod
    def simulate_replay_attack(original_message: dict) -> dict:
        """
        Replay Attack: Re-send an intercepted message
        The message is valid but has already been processed
        """
        # Simply return a copy of the original message
        return original_message.copy()
    
    @staticmethod
    def simulate_message_injection(original_message: dict, injected_content: str = "INJECTED") -> dict:
        """
        Message Injection Attack: Modify the ciphertext
        This should be detected by signature verification failure
        
        Simulates attacker intercepting message IN TRANSIT and modifying it.
        Uses a fresh nonce (as if intercepted before delivery) but keeps
        the original signature which will now be invalid due to modified content.
        """
        tampered = original_message.copy()
        
        # Generate fresh nonce (simulating in-transit interception)
        # This ensures the attack is detected by SIGNATURE check, not REPLAY check
        tampered['nonce'] = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        tampered['timestamp'] = int(time.time())
        
        # Tamper with the ciphertext
        original_ct = base64.b64decode(tampered['ciphertext'])
        # Flip some bits in the middle of ciphertext
        tampered_ct = bytearray(original_ct)
        if len(tampered_ct) > 16:
            for i in range(16, min(32, len(tampered_ct))):
                tampered_ct[i] ^= 0xFF  # Flip bits
        tampered['ciphertext'] = base64.b64encode(bytes(tampered_ct)).decode('utf-8')
        
        # NOTE: The signature is still the ORIGINAL signature
        # It was computed over: original ciphertext + original nonce + original timestamp
        # But now the payload has: tampered ciphertext + new nonce + new timestamp
        # This GUARANTEES signature verification failure
        
        return tampered
    
    @staticmethod
    def simulate_mitm_attack(original_message: dict, attacker_private_key: str) -> dict:
        """
        Man-in-the-Middle Attack: Attacker intercepts and re-signs with their own key
        This demonstrates why we need to verify sender's identity
        
        Simulates attacker intercepting message IN TRANSIT, potentially modifying it,
        and re-signing with their own key. The recipient will verify against the
        REAL sender's public key, causing signature verification to fail.
        """
        mitm_message = original_message.copy()
        
        # Generate fresh nonce (simulating in-transit interception)
        # This ensures the attack is detected by SIGNATURE check, not REPLAY check
        mitm_message['nonce'] = base64.b64encode(get_random_bytes(16)).decode('utf-8')
        mitm_message['timestamp'] = int(time.time())
        
        # Attacker creates new payload and signs with THEIR key
        payload = json.dumps({
            'ciphertext': mitm_message['ciphertext'],
            'iv': mitm_message['iv'],
            'nonce': mitm_message['nonce'],
            'timestamp': mitm_message['timestamp']
        }, sort_keys=True)
        
        # Sign with attacker's key (won't match expected sender's public key)
        # Even though this is a VALID signature, it's made with the WRONG key
        mitm_message['signature'] = RSASignature.sign(payload, attacker_private_key)
        
        return mitm_message
    
    @staticmethod
    def simulate_dos_attack(num_requests: int = 100) -> list:
        """
        DoS Attack Simulation: Generate many requests rapidly
        Returns list of simulated attack requests
        """
        attack_requests = []
        for i in range(num_requests):
            attack_requests.append({
                'id': i,
                'timestamp': time.time(),
                'type': 'message_flood'
            })
        return attack_requests


# ==================== DoS Protection ====================

class RateLimiter:
    """Rate limiting for DoS protection"""
    
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_log = {}  # IP -> list of timestamps
    
    def is_allowed(self, client_id: str) -> tuple:
        """
        Check if request is allowed based on rate limit
        Returns: (allowed: bool, remaining: int, reset_time: int)
        """
        current_time = time.time()
        
        if client_id not in self.request_log:
            self.request_log[client_id] = []
        
        # Clean old entries
        self.request_log[client_id] = [
            t for t in self.request_log[client_id] 
            if current_time - t < self.window_seconds
        ]
        
        requests_in_window = len(self.request_log[client_id])
        remaining = max(0, self.max_requests - requests_in_window)
        
        if requests_in_window >= self.max_requests:
            # Calculate reset time
            oldest = min(self.request_log[client_id])
            reset_time = int(oldest + self.window_seconds - current_time)
            return False, 0, reset_time
        
        # Allow request
        self.request_log[client_id].append(current_time)
        return True, remaining - 1, 0
    
    def get_status(self, client_id: str) -> dict:
        """Get rate limit status for a client"""
        allowed, remaining, reset = self.is_allowed(client_id)
        # Remove the request we just added for status check
        if allowed and client_id in self.request_log:
            self.request_log[client_id].pop()
        
        return {
            'max_requests': self.max_requests,
            'window_seconds': self.window_seconds,
            'remaining': remaining + (1 if allowed else 0),
            'blocked': not allowed,
            'reset_in': reset
        }

