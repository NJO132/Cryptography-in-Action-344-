
import time
import base64
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa


class AttackSimulator:    
    def __init__(self, crypto_manager):

        self.crypto = crypto_manager
    
    def simulate_replay_attack(self, original_payload: Dict[str, Any]) -> Dict[str, Any]:

        replayed_payload = original_payload.copy()
        
        return {
            'attack_type': 'REPLAY_ATTACK',
            'description': 'Attempting to resend a captured message',
            'payload': replayed_payload,
            'expected_result': 'Should be rejected due to expired timestamp'
        }
    
    def simulate_message_injection(self, 
                                    injected_message: str,
       
        # Attacker generates their own key pair
        attacker_private, attacker_public = self.crypto.generate_rsa_keypair()
        
        # Create the malicious message
        session_key = self.crypto.generate_session_key()
        iv = self.crypto.generate_iv()
        
        # Encrypt the injected message
        plaintext_bytes = injected_message.encode('utf-8')
        ciphertext = self.crypto.aes_encrypt(plaintext_bytes, session_key, iv)
        encrypted_session_key = self.crypto.rsa_encrypt(session_key, receiver_public_key)
        
        # Sign with ATTACKER's private key (NOT Alice's!)
        fake_signature = self.crypto.sign_message(ciphertext, attacker_private)
        
        # Construct the forged payload
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
