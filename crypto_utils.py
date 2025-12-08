
# Re-export CryptoManager class
from crypto.messaging import CryptoManager

# Re-export AttackSimulator class
from attacks.attack_simulator import AttackSimulator

# Re-export key generation utility
from crypto.key_management import generate_user_keys

# Re-export helper function
from utils.helpers import bytes_to_hex_display

# Make all exports available
__all__ = [
    'CryptoManager',
    'AttackSimulator', 
    'generate_user_keys',
    'bytes_to_hex_display'
]


# Demo/Test code
if __name__ == "__main__":
    
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
