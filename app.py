"""
================================================================================
APP.PY - Flask Web Application for Secure Messaging
================================================================================
ICS344 Cryptography Project - Secure Messaging Application

This Flask application provides:
- A web interface for secure message exchange between Alice and Bob
- Real-time cryptographic operation logs
- Attack simulation endpoints for educational demonstration
- Rate limiting to defend against DoS attacks

SECURITY DEMONSTRATIONS:
-----------------------
1. CONFIDENTIALITY: AES-256-CBC encryption
2. INTEGRITY: SHA-256 signatures
3. AUTHENTICATION: RSA digital signatures
4. AVAILABILITY: Rate limiting defense

Author: ICS344 Project Team
================================================================================
"""

import os
import json
import time
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, request, jsonify, session

from crypto_utils import CryptoManager, AttackSimulator, generate_user_keys

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Random secret for session management

# ============================================================================
# GLOBAL STATE (In production, use a database!)
# ============================================================================

# Initialize cryptographic manager
crypto_manager = CryptoManager()

# Store for user keys (simulated "Public Key Directory")
# In production, this would be a Certificate Authority or Key Server
user_keys = {}

# Store for exchanged messages
message_store = []

# Store for used nonces (replay attack prevention)
used_nonces = set()

# Store for captured payloads (for attack simulation)
captured_payloads = {}

# MITM attack state
mitm_mode = {
    'active': False,
    'attacker_keys': None
}

# ============================================================================
# RATE LIMITING (DoS DEFENSE)
# ============================================================================

class RateLimiter:
    """
    Simple rate limiter to prevent Denial of Service attacks.
    
    RATE LIMITING EXPLAINED:
    -----------------------
    Rate limiting restricts the number of requests a client can make
    within a time window. This prevents:
    
    1. DoS attacks: Single attacker flooding with requests
    2. DDoS mitigation: Helps (but doesn't fully prevent) distributed attacks
    3. Brute force: Slows down password guessing attempts
    
    ALGORITHM: Token Bucket
    ----------------------
    - Each IP has a "bucket" of tokens
    - Each request consumes a token
    - Tokens regenerate over time
    - When bucket is empty, requests are rejected
    
    CONFIGURATION:
    - RATE_LIMIT: Max requests per window
    - RATE_WINDOW: Time window in seconds
    - BLOCK_DURATION: How long to block after limit exceeded
    """
    
    def __init__(self, rate_limit=10, rate_window=60, block_duration=120):
        """
        Initialize rate limiter.
        
        Args:
            rate_limit: Maximum requests allowed per window
            rate_window: Time window in seconds
            block_duration: How long to block IPs that exceed limit
        """
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.block_duration = block_duration
        
        # Track requests per IP: {ip: [(timestamp1), (timestamp2), ...]}
        self.request_log = defaultdict(list)
        
        # Track blocked IPs: {ip: unblock_timestamp}
        self.blocked_ips = {}
        
        # Statistics for display
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_ips_count': 0
        }
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                # Unblock expired
                del self.blocked_ips[ip]
        return False
    
    def check_rate_limit(self, ip: str) -> dict:
        """
        Check if a request from an IP should be allowed.
        
        Returns:
            Dictionary with:
            - allowed: Boolean
            - reason: String explaining the decision
            - remaining: Requests remaining in window
        """
        current_time = time.time()
        self.stats['total_requests'] += 1
        
        # Check if IP is blocked
        if self.is_blocked(ip):
            self.stats['blocked_requests'] += 1
            remaining_block = int(self.blocked_ips[ip] - current_time)
            return {
                'allowed': False,
                'reason': f'IP blocked for {remaining_block}s due to rate limit violation',
                'remaining': 0,
                'blocked': True
            }
        
        # Clean old requests outside the window
        window_start = current_time - self.rate_window
        self.request_log[ip] = [
            ts for ts in self.request_log[ip] 
            if ts > window_start
        ]
        
        # Check rate limit
        request_count = len(self.request_log[ip])
        
        if request_count >= self.rate_limit:
            # Block this IP
            self.blocked_ips[ip] = current_time + self.block_duration
            self.stats['blocked_ips_count'] += 1
            self.stats['blocked_requests'] += 1
            return {
                'allowed': False,
                'reason': f'Rate limit exceeded ({self.rate_limit} requests/{self.rate_window}s). Blocked for {self.block_duration}s',
                'remaining': 0,
                'blocked': True
            }
        
        # Allow request and log it
        self.request_log[ip].append(current_time)
        remaining = self.rate_limit - request_count - 1
        
        return {
            'allowed': True,
            'reason': 'Request allowed',
            'remaining': remaining,
            'blocked': False
        }
    
    def reset(self):
        """Reset all rate limiting state (for demo purposes)."""
        self.request_log.clear()
        self.blocked_ips.clear()
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_ips_count': 0
        }
    
    def get_stats(self) -> dict:
        """Get current rate limiting statistics."""
        return {
            **self.stats,
            'currently_blocked': list(self.blocked_ips.keys()),
            'rate_limit': self.rate_limit,
            'rate_window': self.rate_window,
            'block_duration': self.block_duration
        }


# Initialize rate limiter
# 10 requests per 60 seconds, block for 120 seconds if exceeded
rate_limiter = RateLimiter(rate_limit=10, rate_window=60, block_duration=120)


def rate_limit_check(f):
    """
    Decorator to apply rate limiting to routes.
    
    Usage:
        @app.route('/api/endpoint')
        @rate_limit_check
        def my_endpoint():
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr or '127.0.0.1'
        check = rate_limiter.check_rate_limit(ip)
        
        if not check['allowed']:
            return jsonify({
                'success': False,
                'error': check['reason'],
                'attack_detected': 'DOS_ATTACK',
                'rate_limit_info': rate_limiter.get_stats()
            }), 429  # 429 = Too Many Requests
        
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_keys():
    """
    Generate RSA key pairs for Alice and Bob on startup.
    
    This simulates the key distribution phase in a real PKI system.
    In production:
    - Keys would be generated on client devices
    - Public keys would be certified by a CA
    - Private keys would never leave the client
    """
    global user_keys
    
    print("[INIT] Generating RSA-2048 key pairs for Alice and Bob...")
    user_keys = generate_user_keys(crypto_manager)
    print("[INIT] ✓ Keys generated and stored in public directory")
    
    # Display public key fingerprints (first 32 chars of public key)
    alice_fingerprint = user_keys['alice']['public_key'][27:59]
    bob_fingerprint = user_keys['bob']['public_key'][27:59]
    print(f"[INIT] Alice's public key fingerprint: {alice_fingerprint}...")
    print(f"[INIT] Bob's public key fingerprint: {bob_fingerprint}...")


# Initialize keys on module load
initialize_keys()


# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route('/')
def index():
    """
    Main dashboard page.
    
    Displays:
    - Sender panel (Alice's view)
    - Receiver panel (Bob's view)
    - Cryptographic operation logs
    - Attack simulation panel
    """
    return render_template('index.html')


@app.route('/api/keys', methods=['GET'])
def get_public_keys():
    """
    Get public keys from the "Public Key Directory".
    
    In a real system, this would be a Certificate Authority or
    Key Distribution Center query.
    
    MITM ATTACK VECTOR:
    ------------------
    If MITM mode is active, this returns the attacker's public key
    instead of the real recipient's key, demonstrating the attack.
    """
    if mitm_mode['active'] and mitm_mode['attacker_keys']:
        # MITM active - return Eve's key as "Bob's" key
        return jsonify({
            'alice_public_key': user_keys['alice']['public_key'],
            'bob_public_key': mitm_mode['attacker_keys']['public_key'],  # Eve's key!
            'mitm_active': True,
            'warning': 'MITM ATTACK ACTIVE - Eve has substituted Bob\'s key!'
        })
    
    return jsonify({
        'alice_public_key': user_keys['alice']['public_key'],
        'bob_public_key': user_keys['bob']['public_key'],
        'mitm_active': False
    })


# ============================================================================
# SECURE MESSAGING ROUTES
# ============================================================================

@app.route('/api/send', methods=['POST'])
@rate_limit_check
def send_message():
    """
    SENDER ENDPOINT - Alice sends a message to Bob.
    
    This endpoint:
    1. Takes plaintext from Alice
    2. Encrypts using the full secure workflow
    3. Returns the encrypted payload and operation logs
    
    The payload would be transmitted to Bob (simulated on the receiver endpoint).
    """
    try:
        data = request.get_json()
        plaintext = data.get('message', '')
        
        if not plaintext:
            return jsonify({
                'success': False,
                'error': 'Message cannot be empty'
            }), 400
        
        # Load sender's private key (Alice)
        sender_private_key = crypto_manager.load_private_key(
            user_keys['alice']['private_key']
        )
        
        # Load receiver's public key (Bob)
        # Note: In MITM mode, this might be Eve's key!
        if mitm_mode['active'] and mitm_mode['attacker_keys']:
            receiver_public_key = crypto_manager.load_public_key(
                mitm_mode['attacker_keys']['public_key']
            )
            mitm_warning = "WARNING: Message encrypted with EVE'S public key (MITM active)!"
        else:
            receiver_public_key = crypto_manager.load_public_key(
                user_keys['bob']['public_key']
            )
            mitm_warning = None
        
        # Create secure payload using the full workflow
        result = crypto_manager.create_secure_payload(
            plaintext=plaintext,
            sender_private_key=sender_private_key,
            receiver_public_key=receiver_public_key
        )
        
        # Store payload for later retrieval/attacks
        payload_id = f"msg_{int(time.time() * 1000)}"
        captured_payloads[payload_id] = result['payload']
        
        # Store in message history
        message_store.append({
            'id': payload_id,
            'sender': 'Alice',
            'receiver': 'Bob',
            'timestamp': datetime.now().isoformat(),
            'payload': result['payload'],
            'status': 'sent'
        })
        
        logs = result['logs']
        if mitm_warning:
            logs.insert(0, f"[⚠️ MITM] {mitm_warning}")
        
        return jsonify({
            'success': True,
            'payload_id': payload_id,
            'payload': result['payload'],
            'logs': logs,
            'session_key_hex': result['session_key_hex'],  # For educational display
            'mitm_active': mitm_mode['active']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/receive', methods=['POST'])
@rate_limit_check
def receive_message():
    """
    RECEIVER ENDPOINT - Bob receives and decrypts a message.
    
    This endpoint:
    1. Takes an encrypted payload
    2. Verifies the signature
    3. Checks for replay attacks
    4. Decrypts the message
    5. Returns the plaintext and operation logs
    """
    global used_nonces
    
    try:
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({
                'success': False,
                'error': 'No payload provided'
            }), 400
        
        # Load receiver's private key (Bob)
        receiver_private_key = crypto_manager.load_private_key(
            user_keys['bob']['private_key']
        )
        
        # Load sender's public key (Alice)
        sender_public_key = crypto_manager.load_public_key(
            user_keys['alice']['public_key']
        )
        
        # Process the received payload
        result = crypto_manager.process_received_payload(
            payload=payload,
            receiver_private_key=receiver_private_key,
            sender_public_key=sender_public_key,
            replay_window=60,
            used_nonces=used_nonces
        )
        
        # Update message store
        for msg in message_store:
            if msg['payload'] == payload:
                msg['status'] = 'received' if result['success'] else 'rejected'
                msg['decrypted'] = result.get('plaintext', None)
                break
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# ATTACK SIMULATION ROUTES
# ============================================================================

@app.route('/api/attack/replay', methods=['POST'])
@rate_limit_check
def replay_attack():
    """
    REPLAY ATTACK SIMULATION
    
    This endpoint demonstrates a replay attack by:
    1. Taking a previously captured message payload
    2. Resending it as if it were new
    3. The receiver should reject it due to expired timestamp
    
    EDUCATIONAL PURPOSE:
    -------------------
    Shows why timestamps/nonces are crucial for preventing
    attackers from re-using captured messages.
    """
    try:
        data = request.get_json()
        payload_id = data.get('payload_id')
        
        # Get the captured payload
        if payload_id and payload_id in captured_payloads:
            payload = captured_payloads[payload_id]
        else:
            # Use the most recent payload
            if not captured_payloads:
                return jsonify({
                    'success': False,
                    'error': 'No captured payloads available. Send a message first!'
                }), 400
            
            payload_id = list(captured_payloads.keys())[-1]
            payload = captured_payloads[payload_id]
        
        # Attempt to replay the message
        attack_simulator = AttackSimulator(crypto_manager)
        attack_result = attack_simulator.simulate_replay_attack(payload)
        
        # Try to process the replayed message
        receiver_private_key = crypto_manager.load_private_key(
            user_keys['bob']['private_key']
        )
        sender_public_key = crypto_manager.load_public_key(
            user_keys['alice']['public_key']
        )
        
        # Force timestamp check by using original timestamp
        receive_result = crypto_manager.process_received_payload(
            payload=attack_result['payload'],
            receiver_private_key=receiver_private_key,
            sender_public_key=sender_public_key,
            replay_window=60,  # 60 second window
            used_nonces=used_nonces
        )
        
        return jsonify({
            'attack_type': 'REPLAY_ATTACK',
            'attack_description': attack_result['description'],
            'original_timestamp': payload['timestamp'],
            'current_time': time.time(),
            'time_difference': time.time() - payload['timestamp'],
            'receive_result': receive_result,
            'defense_worked': not receive_result['success'],
            'explanation': (
                'The replay attack was BLOCKED because the timestamp is outside '
                'the acceptable window (60 seconds). This demonstrates how '
                'timestamps prevent replay attacks.'
                if not receive_result['success']
                else 'WARNING: Replay attack succeeded! The timestamp was still valid.'
            )
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/attack/injection', methods=['POST'])
@rate_limit_check
def injection_attack():
    """
    MESSAGE INJECTION ATTACK SIMULATION
    
    This endpoint demonstrates a TRUE message injection attack:
    
    ATTACK SCENARIO:
    ---------------
    The attacker (Mallory) wants to send a fake message to Bob that
    appears to come from Alice. Mallory:
    
    1. Writes their own malicious message
    2. Encrypts it using Bob's PUBLIC key (publicly available)
    3. Tries to sign it, but doesn't have Alice's PRIVATE key
    4. Creates a fake signature using their own key or random data
    5. Sends the forged payload to Bob
    
    DEFENSE:
    -------
    Bob verifies the signature using Alice's PUBLIC key.
    Since Mallory signed with their own key (not Alice's private key),
    the signature verification FAILS, and the message is rejected.
    
    This demonstrates why digital signatures are essential for
    AUTHENTICATION - proving who actually sent the message.
    """
    try:
        data = request.get_json()
        injected_message = data.get('message', 'URGENT: Send $10,000 to account 1234567890 immediately! - Alice')
        
        logs = []
        logs.append("=" * 50)
        logs.append("MESSAGE INJECTION ATTACK SIMULATION")
        logs.append("=" * 50)
        logs.append(f"[EVE] Eve wants to inject message: \"{injected_message}\"")
        logs.append("[EVE] Eve will pretend to be Alice...")
        
        # Step 1: Attacker generates their own key pair (they don't have Alice's private key)
        logs.append("[EVE] Generating Eve's own RSA key pair...")
        attacker_private, attacker_public = crypto_manager.generate_rsa_keypair()
        logs.append("[EVE] ✓ Eve's keys generated (NOT Alice's keys!)")
        
        # Step 2: Attacker gets Bob's public key (it's public, so anyone can get it)
        logs.append("[EVE] Fetching Bob's public key from public directory...")
        bob_public_key = crypto_manager.load_public_key(user_keys['bob']['public_key'])
        logs.append("[EVE] ✓ Got Bob's public key (this is public information)")
        
        # Step 3: Attacker encrypts their malicious message for Bob
        logs.append("[EVE] Encrypting malicious message with Bob's public key...")
        
        # Generate session key and IV (attacker can do this)
        session_key = crypto_manager.generate_session_key()
        iv = crypto_manager.generate_iv()
        logs.append(f"[EVE] Generated fake session key: {session_key.hex()[:32]}...")
        logs.append(f"[EVE] Generated IV: {iv.hex()}")
        
        # Encrypt the malicious message
        plaintext_bytes = injected_message.encode('utf-8')
        ciphertext = crypto_manager.aes_encrypt(plaintext_bytes, session_key, iv)
        logs.append(f"[EVE] Encrypted message: {ciphertext.hex()[:32]}...")
        
        # Encrypt session key with Bob's public key
        encrypted_session_key = crypto_manager.rsa_encrypt(session_key, bob_public_key)
        logs.append("[EVE] ✓ Session key encrypted with Bob's public key")
        
        # Step 4: Attacker tries to sign - but uses THEIR OWN private key (not Alice's!)
        logs.append("[EVE] Attempting to sign message...")
        logs.append("[EVE] ⚠ Problem: Eve doesn't have Alice's private key!")
        logs.append("[EVE] ⚠ Eve will sign with her OWN private key instead...")
        
        # Sign with attacker's key (NOT Alice's key!)
        fake_signature = crypto_manager.sign_message(ciphertext, attacker_private)
        logs.append(f"[EVE] Created FAKE signature: {fake_signature.hex()[:32]}...")
        logs.append("[EVE] ⚠ This signature was made with EVE's key, not Alice's!")
        
        # Step 5: Construct the forged payload
        import base64
        forged_payload = {
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'signature': base64.b64encode(fake_signature).decode('utf-8'),
            'timestamp': time.time()  # Fresh timestamp
        }
        
        logs.append("[EVE] ✓ Forged payload constructed")
        logs.append("[EVE] Sending forged message to Bob...")
        logs.append("")
        logs.append("=" * 50)
        logs.append("BOB RECEIVES THE FORGED MESSAGE")
        logs.append("=" * 50)
        
        # Step 6: Bob tries to process the message
        receiver_private_key = crypto_manager.load_private_key(user_keys['bob']['private_key'])
        sender_public_key = crypto_manager.load_public_key(user_keys['alice']['public_key'])
        
        logs.append("[BOB] Received a message claiming to be from Alice...")
        logs.append("[BOB] Step 1: Verifying signature with ALICE's public key...")
        
        # Verify signature - this should FAIL because it was signed with attacker's key
        signature_valid = crypto_manager.verify_signature(
            ciphertext, 
            fake_signature, 
            sender_public_key  # Alice's public key
        )
        
        if signature_valid:
            logs.append("[BOB] ✓ Signature valid")
            defense_worked = False
        else:
            logs.append("[BOB] ❌ SIGNATURE VERIFICATION FAILED!")
            logs.append("[BOB] The signature does not match Alice's public key!")
            logs.append("[BOB] This message was NOT sent by Alice!")
            logs.append("[BOB] REJECTING MESSAGE - Possible injection attack detected!")
            defense_worked = True
        
        logs.append("")
        logs.append("=" * 50)
        logs.append("ATTACK RESULT")
        logs.append("=" * 50)
        
        if defense_worked:
            logs.append("[DEFENSE] ✓ MESSAGE INJECTION BLOCKED!")
            logs.append("[DEFENSE] Bob correctly rejected the forged message.")
            logs.append("[DEFENSE] The attacker could not impersonate Alice.")
            logs.append("[REASON] Without Alice's private key, the attacker")
            logs.append("         cannot create a valid signature that matches")
            logs.append("         Alice's public key.")
        else:
            logs.append("[ATTACK] ⚠ MESSAGE INJECTION SUCCEEDED!")
            logs.append("[ATTACK] This should NOT happen in a secure system!")
        
        return jsonify({
            'attack_type': 'MESSAGE_INJECTION',
            'attack_description': (
                f'Eve crafted a fake message: "{injected_message}" '
                'and tried to send it to Bob pretending to be Alice. '
                'Eve encrypted it properly with Bob\'s public key, '
                'but could NOT create a valid signature without Alice\'s private key.'
            ),
            'injected_message': injected_message,
            'forged_payload': {
                'ciphertext_preview': forged_payload['ciphertext'][:64] + '...',
                'signature_preview': forged_payload['signature'][:64] + '...',
                'timestamp': forged_payload['timestamp']
            },
            'signature_valid': signature_valid,
            'defense_worked': defense_worked,
            'logs': logs,
            'explanation': (
                'The injection attack was BLOCKED because the signature verification '
                'failed. Eve does not have Alice\'s private key, '
                'so she cannot create a signature that Bob can verify with Alice\'s '
                'public key. This demonstrates how digital signatures provide '
                'AUTHENTICATION - proving the message actually came from Alice.'
                if defense_worked
                else 'WARNING: Injection attack succeeded! This should not happen.'
            )
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/attack/mitm/enable', methods=['POST'])
def enable_mitm():
    """
    ENABLE MAN-IN-THE-MIDDLE ATTACK MODE
    
    This simulates an attacker who has compromised the public key
    directory and substituted their own public key for Bob's.
    
    When MITM is active:
    - GET /api/keys returns the attacker's key as "Bob's" key
    - Messages sent to "Bob" are actually encrypted with attacker's key
    - Attacker can decrypt these messages
    """
    global mitm_mode
    
    # Generate attacker's key pair
    attacker_private, attacker_public = crypto_manager.generate_rsa_keypair()
    
    mitm_mode['active'] = True
    mitm_mode['attacker_keys'] = {
        'private_key': crypto_manager.serialize_private_key(attacker_private),
        'public_key': crypto_manager.serialize_public_key(attacker_public)
    }
    
    return jsonify({
        'success': True,
        'message': 'MITM attack enabled! Eve\'s key has replaced Bob\'s key in the directory.',
        'attacker_public_key_preview': mitm_mode['attacker_keys']['public_key'][:100] + '...',
        'original_bob_key_preview': user_keys['bob']['public_key'][:100] + '...',
        'explanation': (
            'Eve has substituted her public key for Bob\'s in the '
            'public key directory. Any messages Alice sends to "Bob" will now '
            'be encrypted with EVE\'s public key, allowing Eve '
            'to decrypt them.'
        )
    })


@app.route('/api/attack/mitm/disable', methods=['POST'])
def disable_mitm():
    """Disable MITM attack mode and restore legitimate keys."""
    global mitm_mode
    
    mitm_mode['active'] = False
    mitm_mode['attacker_keys'] = None
    
    return jsonify({
        'success': True,
        'message': 'MITM attack disabled. Bob\'s legitimate key restored.'
    })


@app.route('/api/attack/mitm/decrypt', methods=['POST'])
@rate_limit_check
def mitm_decrypt():
    """
    ATTACKER'S DECRYPTION - Demonstrates MITM attack success
    
    When MITM is active, messages sent to "Bob" are actually encrypted
    with the attacker's public key. This endpoint shows the attacker
    decrypting intercepted messages.
    """
    try:
        if not mitm_mode['active'] or not mitm_mode['attacker_keys']:
            return jsonify({
                'success': False,
                'error': 'MITM mode is not active. Enable it first!'
            }), 400
        
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({
                'success': False,
                'error': 'No payload provided'
            }), 400
        
        # Attacker attempts to decrypt with their private key
        attacker_private_key = crypto_manager.load_private_key(
            mitm_mode['attacker_keys']['private_key']
        )
        
        # Note: Signature will fail because Alice signed with her key
        # But attacker can still decrypt the session key and message!
        
        logs = []
        logs.append("[EVE] Attempting to decrypt intercepted message...")
        
        try:
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.padding import PKCS7
            
            # Decode payload
            encrypted_session_key = base64.b64decode(payload['encrypted_session_key'])
            iv = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            
            # Decrypt session key with attacker's private key
            session_key = crypto_manager.rsa_decrypt(encrypted_session_key, attacker_private_key)
            logs.append(f"[EVE] ✓ Decrypted session key: {session_key.hex()}")
            
            # Decrypt message
            plaintext_bytes = crypto_manager.aes_decrypt(ciphertext, session_key, iv)
            plaintext = plaintext_bytes.decode('utf-8')
            logs.append(f"[EVE] ✓ Decrypted message: {plaintext}")
            
            return jsonify({
                'success': True,
                'attack_type': 'MITM_ATTACK',
                'intercepted_message': plaintext,
                'session_key': session_key.hex(),
                'logs': logs,
                'explanation': (
                    'SUCCESS! Eve was able to decrypt the message because '
                    'Alice unknowingly encrypted it with EVE\'s public key '
                    '(which was substituted for Bob\'s key in the directory). '
                    'This demonstrates why secure key exchange and certificate '
                    'verification are crucial!'
                )
            })
            
        except Exception as e:
            logs.append(f"[EVE] ✗ Decryption failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Eve\'s decryption failed: {str(e)}',
                'logs': logs,
                'explanation': (
                    'The message was not encrypted with Eve\'s key. '
                    'Make sure MITM mode was active when the message was SENT.'
                )
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/attack/dos/status', methods=['GET'])
def dos_status():
    """Get current DoS defense status and statistics."""
    return jsonify({
        'rate_limiter_stats': rate_limiter.get_stats(),
        'your_ip': request.remote_addr or '127.0.0.1',
        'explanation': (
            f'Rate limit: {rate_limiter.rate_limit} requests per {rate_limiter.rate_window} seconds. '
            f'Violators are blocked for {rate_limiter.block_duration} seconds.'
        )
    })


@app.route('/api/attack/dos/reset', methods=['POST'])
def dos_reset():
    """Reset rate limiter state (for demo purposes)."""
    rate_limiter.reset()
    return jsonify({
        'success': True,
        'message': 'Rate limiter reset. All IPs unblocked.'
    })


@app.route('/api/attack/dos/test', methods=['POST'])
@rate_limit_check
def dos_test_endpoint():
    """
    DoS TEST ENDPOINT
    
    This endpoint is rate-limited. Use it to test the DoS defense
    by making rapid requests.
    """
    ip = request.remote_addr or '127.0.0.1'
    remaining = rate_limiter.rate_limit - len(rate_limiter.request_log.get(ip, []))
    
    return jsonify({
        'success': True,
        'message': 'Request successful',
        'your_ip': ip,
        'requests_remaining': remaining,
        'rate_limit_stats': rate_limiter.get_stats()
    })


# ============================================================================
# UTILITY ROUTES
# ============================================================================

@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Get all exchanged messages (for display purposes)."""
    return jsonify({
        'messages': message_store,
        'captured_payloads': list(captured_payloads.keys())
    })


@app.route('/api/reset', methods=['POST'])
def reset_state():
    """Reset all application state (for demo purposes)."""
    global message_store, used_nonces, captured_payloads, mitm_mode
    
    message_store = []
    used_nonces = set()
    captured_payloads = {}
    mitm_mode = {'active': False, 'attacker_keys': None}
    rate_limiter.reset()
    
    # Regenerate keys
    initialize_keys()
    
    return jsonify({
        'success': True,
        'message': 'All state reset. New keys generated.'
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(429)
def ratelimit_error(e):
    """Handle rate limit exceeded errors."""
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'attack_detected': 'DOS_ATTACK',
        'message': str(e)
    }), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors."""
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': str(e)
    }), 500


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("SECURE MESSAGING APPLICATION")
    print("ICS344 Cryptography Project")
    print("=" * 70)
    print("\n[INFO] Starting Flask server...")
    print("[INFO] Access the dashboard at: http://127.0.0.1:5000")
    print("[INFO] Rate limiting enabled: 10 requests/60s per IP")
    print("\n[SECURITY FEATURES]")
    print("  • AES-256-CBC encryption with PKCS#7 padding")
    print("  • RSA-2048 key exchange and digital signatures")
    print("  • Timestamp-based replay attack prevention")
    print("  • Rate limiting for DoS protection")
    print("\n[ATTACK SIMULATIONS]")
    print("  • Replay Attack: /api/attack/replay")
    print("  • Message Injection: /api/attack/injection")
    print("  • Man-in-the-Middle: /api/attack/mitm/*")
    print("  • DoS Test: /api/attack/dos/*")
    print("\n" + "=" * 70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

