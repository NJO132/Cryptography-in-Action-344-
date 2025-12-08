

import time
import base64
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.constants import AES_BLOCK_SIZE, AES_KEY_SIZE, IV_SIZE, BACKEND
from crypto.key_management import (
    generate_rsa_keypair, serialize_public_key, serialize_private_key,
    load_public_key, load_private_key
)
from crypto.encryption import generate_session_key, generate_iv, aes_encrypt, rsa_encrypt, pad_message
from crypto.decryption import aes_decrypt, rsa_decrypt, unpad_message
from crypto.signing import sign_message, verify_signature


class CryptoManager:
    """Manages cryptographic operations for secure messaging."""
    
    AES_BLOCK_SIZE = AES_BLOCK_SIZE
    AES_KEY_SIZE = AES_KEY_SIZE
    IV_SIZE = IV_SIZE
    
    def __init__(self):
        self.backend = BACKEND
    
    # Key Management (delegate to module functions)
    def generate_rsa_keypair(self):
        return generate_rsa_keypair()
    
    def serialize_public_key(self, public_key):
        return serialize_public_key(public_key)
    
    def serialize_private_key(self, private_key):
        return serialize_private_key(private_key)
    
    def load_public_key(self, pem_data):
        return load_public_key(pem_data)
    
    def load_private_key(self, pem_data):
        return load_private_key(pem_data)
    
    # Encryption (delegate to module functions)
    def generate_session_key(self):
        return generate_session_key()
    
    def generate_iv(self):
        return generate_iv()
    
    def pad_message(self, plaintext):
        return pad_message(plaintext)
    
    def aes_encrypt(self, plaintext, key, iv):
        return aes_encrypt(plaintext, key, iv)
    
    def rsa_encrypt(self, data, public_key):
        return rsa_encrypt(data, public_key)
    
    # Decryption (delegate to module functions)
    def unpad_message(self, padded_text):
        return unpad_message(padded_text)
    
    def aes_decrypt(self, ciphertext, key, iv):
        return aes_decrypt(ciphertext, key, iv)
    
    def rsa_decrypt(self, ciphertext, private_key):
        return rsa_decrypt(ciphertext, private_key)
    
    # Signing (delegate to module functions)
    def sign_message(self, message, private_key):
        return sign_message(message, private_key)
    
    def verify_signature(self, message, signature, public_key):
        return verify_signature(message, signature, public_key)
    
    # High-level Messaging Workflows
    
    def create_secure_payload(self, plaintext: str, 
                               sender_private_key: rsa.RSAPrivateKey,
                               receiver_public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        """Create a complete encrypted and signed message payload."""
        logs = []
        
        # STEP 1: Generate Session Key
        session_key = self.generate_session_key()
        logs.append(f"[STEP 1] Generated AES-256 Session Key: {session_key.hex()}")
        
        # STEP 2: Generate IV
        iv = self.generate_iv()
        logs.append(f"[STEP 2] Generated IV (16 bytes): {iv.hex()}")
        
        # STEP 3: Encrypt Message with AES-CBC
        plaintext_bytes = plaintext.encode('utf-8')
        logs.append(f"[STEP 3] Original Message: {plaintext}")
        logs.append(f"[STEP 3] Message as bytes: {plaintext_bytes.hex()}")
        
        ciphertext = self.aes_encrypt(plaintext_bytes, session_key, iv)
        logs.append(f"[STEP 3] AES-CBC Ciphertext: {ciphertext.hex()}")
        
        # STEP 4: Encrypt Session Key with RSA
        encrypted_session_key = self.rsa_encrypt(session_key, receiver_public_key)
        logs.append(f"[STEP 4] RSA-Encrypted Session Key: {encrypted_session_key.hex()[:64]}...")
        
        # STEP 5: Sign the Ciphertext
        signature = self.sign_message(ciphertext, sender_private_key)
        logs.append(f"[STEP 5] RSA-SHA256 Signature: {signature.hex()[:64]}...")
        
        # STEP 6: Add Timestamp
        timestamp = time.time()
        logs.append(f"[STEP 6] Timestamp: {timestamp}")
        
        # Construct Final Payload
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
            'session_key_hex': session_key.hex()
        }
    
    def process_received_payload(self, payload: Dict[str, Any],
                                  receiver_private_key: rsa.RSAPrivateKey,
                                  sender_public_key: rsa.RSAPublicKey,
                                  replay_window: int = 60,
                                  used_nonces: Optional[set] = None) -> Dict[str, Any]:
        """Process and decrypt a received message payload."""
        logs = []
        try:
            # Decode Base64 Data
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
            
            # STEP 1: Verify Signature
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
            
            # STEP 2: Check Timestamp (Replay Attack Defense)
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
            
            # Check for nonce reuse
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
            
            # STEP 3: Decrypt Session Key
            logs.append("[STEP 3] Decrypting session key with receiver's private key...")
            
            session_key = self.rsa_decrypt(encrypted_session_key, receiver_private_key)
            logs.append(f"[STEP 3] Recovered Session Key: {session_key.hex()}")
            
            # STEP 4: Decrypt Message
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
