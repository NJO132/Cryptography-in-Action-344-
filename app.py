import os
import json
import time
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, request, jsonify, session

from crypto_utils import CryptoManager, AttackSimulator, generate_user_keys

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Global state
crypto_manager = CryptoManager()
user_keys = {}
message_store = []
used_nonces = set()
captured_payloads = {}
session_established = False  # True after keys are exchanged, before any message
mitm_mode = {
    'active': False,
    'eve_keys': None,  # Eve's key pair (she uses same keys for both directions)
    'intercepted': {},
    'alice_original_public': None,  # Store original keys for reference
    'bob_original_public': None
}


class RateLimiter:
    """Simple rate limiter to prevent DoS attacks."""
    
    def __init__(self, rate_limit=10, rate_window=60, block_duration=120):
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.block_duration = block_duration
        self.request_log = defaultdict(list)
        self.blocked_ips = {}
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_ips_count': 0
        }
    
    def is_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
        return False
    
    def check_rate_limit(self, ip: str) -> dict:
        current_time = time.time()
        self.stats['total_requests'] += 1
        
        if self.is_blocked(ip):
            self.stats['blocked_requests'] += 1
            remaining_block = int(self.blocked_ips[ip] - current_time)
            return {
                'allowed': False,
                'reason': f'IP blocked for {remaining_block}s due to rate limit violation',
                'remaining': 0,
                'blocked': True
            }
        
        window_start = current_time - self.rate_window
        self.request_log[ip] = [ts for ts in self.request_log[ip] if ts > window_start]
        request_count = len(self.request_log[ip])
        
        if request_count >= self.rate_limit:
            self.blocked_ips[ip] = current_time + self.block_duration
            self.stats['blocked_ips_count'] += 1
            self.stats['blocked_requests'] += 1
            return {
                'allowed': False,
                'reason': f'Rate limit exceeded ({self.rate_limit} requests/{self.rate_window}s). Blocked for {self.block_duration}s',
                'remaining': 0,
                'blocked': True
            }
        
        self.request_log[ip].append(current_time)
        remaining = self.rate_limit - request_count - 1
        
        return {
            'allowed': True,
            'reason': 'Request allowed',
            'remaining': remaining,
            'blocked': False
        }
    
    def reset(self):
        self.request_log.clear()
        self.blocked_ips.clear()
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_ips_count': 0
        }
    
    def get_stats(self) -> dict:
        return {
            **self.stats,
            'currently_blocked': list(self.blocked_ips.keys()),
            'rate_limit': self.rate_limit,
            'rate_window': self.rate_window,
            'block_duration': self.block_duration
        }


rate_limiter = RateLimiter(rate_limit=10, rate_window=60, block_duration=120)


def rate_limit_check(f):
    """Decorator to apply rate limiting to routes."""
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
            }), 429
        
        return f(*args, **kwargs)
    return decorated_function


def initialize_keys():
    """Generate RSA key pairs for Alice and Bob."""
    global user_keys
    print("[INIT] Generating RSA-2048 key pairs for Alice and Bob...")
    user_keys = generate_user_keys(crypto_manager)
    print("[INIT] ✓ Keys generated and stored in public directory")
    alice_fingerprint = user_keys['alice']['public_key'][27:59]
    bob_fingerprint = user_keys['bob']['public_key'][27:59]
    print(f"[INIT] Alice's public key fingerprint: {alice_fingerprint}...")
    print(f"[INIT] Bob's public key fingerprint: {bob_fingerprint}...")


initialize_keys()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/keys', methods=['GET'])
def get_public_keys():
    """
    Get public keys for key exchange phase.
    If MITM is active, Eve's public key is returned to BOTH parties:
    - Alice receives Eve's key (thinking it's Bob's)
    - Bob receives Eve's key (thinking it's Alice's)
    """
    requester = request.args.get('requester', 'both')  # 'alice', 'bob', or 'both'
    
    if mitm_mode['active'] and mitm_mode['eve_keys']:
        eve_public = mitm_mode['eve_keys']['public_key']
        
        if requester == 'alice':
            # Alice asks for Bob's key -> Eve gives her own key
            return jsonify({
                'bob_public_key': eve_public,  # Eve's key, not Bob's!
                'mitm_active': True,
                'warning': 'MITM: Alice received EVE\'s key instead of Bob\'s!'
            })
        elif requester == 'bob':
            # Bob asks for Alice's key -> Eve gives her own key
            return jsonify({
                'alice_public_key': eve_public,  # Eve's key, not Alice's!
                'mitm_active': True,
                'warning': 'MITM: Bob received EVE\'s key instead of Alice\'s!'
            })
        else:
            # Return both (showing the attack clearly)
            return jsonify({
                'alice_public_key': eve_public,  # What Bob sees (Eve's key)
                'bob_public_key': eve_public,    # What Alice sees (Eve's key)
                'mitm_active': True,
                'warning': 'MITM ACTIVE: Eve has substituted BOTH keys! She sits in the middle.',
                'eve_public_key': eve_public,
                'real_alice_public_key': mitm_mode['alice_original_public'],
                'real_bob_public_key': mitm_mode['bob_original_public']
            })
    
    return jsonify({
        'alice_public_key': user_keys['alice']['public_key'],
        'bob_public_key': user_keys['bob']['public_key'],
        'mitm_active': False,
        'session_established': session_established
    })


@app.route('/api/send', methods=['POST'])
@rate_limit_check
def send_message():
    """Alice sends encrypted message to Bob."""
    global session_established
    
    try:
        data = request.get_json()
        plaintext = data.get('message', '')
        
        if not plaintext:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
        
        # Mark session as established after first message attempt
        session_established = True
        
        sender_private_key = crypto_manager.load_private_key(user_keys['alice']['private_key'])
        
        # If MITM is active, Alice encrypts with Eve's public key (thinking it's Bob's)
        if mitm_mode['active'] and mitm_mode['eve_keys']:
            receiver_public_key = crypto_manager.load_public_key(mitm_mode['eve_keys']['public_key'])
            mitm_warning = "WARNING: Alice encrypted with EVE'S public key (she thinks it's Bob's)!"
        else:
            receiver_public_key = crypto_manager.load_public_key(user_keys['bob']['public_key'])
            mitm_warning = None
        
        result = crypto_manager.create_secure_payload(
            plaintext=plaintext,
            sender_private_key=sender_private_key,
            receiver_public_key=receiver_public_key
        )
        
        payload_id = f"msg_{int(time.time() * 1000)}"
        captured_payloads[payload_id] = result['payload']
        
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
            'session_key_hex': result['session_key_hex'],
            'mitm_active': mitm_mode['active']
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/receive', methods=['POST'])
@rate_limit_check
def receive_message():
    """
    Bob receives and decrypts message.
    
    IMPORTANT FOR MITM: If MITM is active, Bob uses Eve's public key
    (thinking it's Alice's) to verify signatures. This means Eve's
    signatures will PASS verification!
    """
    global used_nonces
    
    try:
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({'success': False, 'error': 'No payload provided'}), 400
        
        receiver_private_key = crypto_manager.load_private_key(user_keys['bob']['private_key'])
        
        # CRITICAL: If MITM is active, Bob uses Eve's public key (thinking it's Alice's)
        # This is why MITM succeeds - Bob will accept Eve's signatures!
        if mitm_mode['active'] and mitm_mode['eve_keys']:
            # Bob thinks this is Alice's key, but it's actually Eve's!
            sender_public_key = crypto_manager.load_public_key(mitm_mode['eve_keys']['public_key'])
            mitm_note = "[MITM] Bob is verifying with EVE's key (he thinks it's Alice's)!"
        else:
            sender_public_key = crypto_manager.load_public_key(user_keys['alice']['public_key'])
            mitm_note = None
        
        result = crypto_manager.process_received_payload(
            payload=payload,
            receiver_private_key=receiver_private_key,
            sender_public_key=sender_public_key,
            replay_window=60,
            used_nonces=used_nonces
        )
        
        # Add MITM warning to logs if applicable
        if mitm_note and 'logs' in result:
            result['logs'].insert(0, "=" * 50)
            result['logs'].insert(1, "⚠️  MAN-IN-THE-MIDDLE ATTACK ACTIVE")
            result['logs'].insert(2, "=" * 50)
            result['logs'].insert(3, mitm_note)
            result['logs'].insert(4, "[MITM] If Eve signed this, verification will PASS!")
            result['logs'].insert(5, "[MITM] Bob has no way to know he's being fooled.")
            result['logs'].insert(6, "")
        
        for msg in message_store:
            if msg['payload'] == payload:
                msg['status'] = 'received' if result['success'] else 'rejected'
                msg['decrypted'] = result.get('plaintext', None)
                break
        
        # Add explanation about why MITM succeeded (if it did)
        if mitm_mode['active'] and result.get('success'):
            result['mitm_warning'] = (
                'MITM ATTACK SUCCEEDED! Bob accepted this message thinking it was from Alice. '
                'The signature verified because Bob used Eve\'s public key (thinking it was Alice\'s). '
                'Digital signatures alone CANNOT prevent MITM at the key exchange phase. '
                'DIGITAL CERTIFICATES are needed to bind identities to public keys.'
            )
            result['mitm_active'] = True
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/replay', methods=['POST'])
@rate_limit_check
def replay_attack():
    """Simulate replay attack using captured payload."""
    try:
        data = request.get_json()
        payload_id = data.get('payload_id')
        
        if payload_id and payload_id in captured_payloads:
            payload = captured_payloads[payload_id]
        else:
            if not captured_payloads:
                return jsonify({
                    'success': False,
                    'error': 'No captured payloads available. Send a message first!'
                }), 400
            payload_id = list(captured_payloads.keys())[-1]
            payload = captured_payloads[payload_id]
        
        attack_simulator = AttackSimulator(crypto_manager)
        attack_result = attack_simulator.simulate_replay_attack(payload)
        
        receiver_private_key = crypto_manager.load_private_key(user_keys['bob']['private_key'])
        sender_public_key = crypto_manager.load_public_key(user_keys['alice']['public_key'])
        
        receive_result = crypto_manager.process_received_payload(
            payload=attack_result['payload'],
            receiver_private_key=receiver_private_key,
            sender_public_key=sender_public_key,
            replay_window=60,
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
                'the acceptable window (60 seconds).'
                if not receive_result['success']
                else 'WARNING: Replay attack succeeded! The timestamp was still valid.'
            )
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/injection', methods=['POST'])
@rate_limit_check
def injection_attack():
    """Simulate message injection attack - attacker tries to forge a message."""
    try:
        data = request.get_json()
        injected_message = data.get('message', 'URGENT: Send $10,000 to account 1234567890 immediately! - Alice')
        
        logs = []
        logs.append("=" * 50)
        logs.append("MESSAGE INJECTION ATTACK SIMULATION")
        logs.append("=" * 50)
        logs.append(f"[EVE] Eve wants to inject message: \"{injected_message}\"")
        logs.append("[EVE] Eve will pretend to be Alice...")
        
        logs.append("[EVE] Generating Eve's own RSA key pair...")
        attacker_private, attacker_public = crypto_manager.generate_rsa_keypair()
        logs.append("[EVE] ✓ Eve's keys generated (NOT Alice's keys!)")
        
        logs.append("[EVE] Fetching Bob's public key from public directory...")
        bob_public_key = crypto_manager.load_public_key(user_keys['bob']['public_key'])
        logs.append("[EVE] ✓ Got Bob's public key (this is public information)")
        
        logs.append("[EVE] Encrypting malicious message with Bob's public key...")
        
        session_key = crypto_manager.generate_session_key()
        iv = crypto_manager.generate_iv()
        logs.append(f"[EVE] Generated fake session key: {session_key.hex()[:32]}...")
        logs.append(f"[EVE] Generated IV: {iv.hex()}")
        
        plaintext_bytes = injected_message.encode('utf-8')
        ciphertext = crypto_manager.aes_encrypt(plaintext_bytes, session_key, iv)
        logs.append(f"[EVE] Encrypted message: {ciphertext.hex()[:32]}...")
        
        encrypted_session_key = crypto_manager.rsa_encrypt(session_key, bob_public_key)
        logs.append("[EVE] ✓ Session key encrypted with Bob's public key")
        
        logs.append("[EVE] Attempting to sign message...")
        logs.append("[EVE] ⚠ Problem: Eve doesn't have Alice's private key!")
        logs.append("[EVE] ⚠ Eve will sign with her OWN private key instead...")
        
        fake_signature = crypto_manager.sign_message(ciphertext, attacker_private)
        logs.append(f"[EVE] Created FAKE signature: {fake_signature.hex()[:32]}...")
        logs.append("[EVE] ⚠ This signature was made with EVE's key, not Alice's!")
        
        import base64
        forged_payload = {
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'signature': base64.b64encode(fake_signature).decode('utf-8'),
            'timestamp': time.time()
        }
        
        logs.append("[EVE] ✓ Forged payload constructed")
        logs.append("[EVE] Sending forged message to Bob...")
        logs.append("")
        logs.append("=" * 50)
        logs.append("BOB RECEIVES THE FORGED MESSAGE")
        logs.append("=" * 50)
        
        receiver_private_key = crypto_manager.load_private_key(user_keys['bob']['private_key'])
        sender_public_key = crypto_manager.load_public_key(user_keys['alice']['public_key'])
        
        logs.append("[BOB] Received a message claiming to be from Alice...")
        logs.append("[BOB] Step 1: Verifying signature with ALICE's public key...")
        
        signature_valid = crypto_manager.verify_signature(ciphertext, fake_signature, sender_public_key)
        
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
        else:
            logs.append("[ATTACK] ⚠ MESSAGE INJECTION SUCCEEDED!")
        
        return jsonify({
            'attack_type': 'MESSAGE_INJECTION',
            'attack_description': (
                f'Eve crafted a fake message: "{injected_message}" '
                'and tried to send it to Bob pretending to be Alice.'
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
                'The injection attack was BLOCKED because signature verification failed. '
                'Eve cannot create a valid signature without Alice\'s private key.'
                if defense_worked
                else 'WARNING: Injection attack succeeded!'
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
    Enable MITM attack at the KEY EXCHANGE PHASE.
    
    This attack only works BEFORE any messages are sent.
    Eve intercepts the key exchange and provides her public key to BOTH parties:
    - Alice receives Eve's key (thinking it's Bob's)
    - Bob receives Eve's key (thinking it's Alice's)
    
    This allows Eve to decrypt messages from both directions.
    """
    global mitm_mode
    
    # MITM attack only works at the key exchange phase (before messages are sent)
    if session_established:
        return jsonify({
            'success': False,
            'error': 'MITM attack failed! Session already established.',
            'explanation': (
                'The Man-in-the-Middle attack only works during the KEY EXCHANGE PHASE, '
                'before any messages are sent. Once Alice and Bob have exchanged keys and '
                'started communicating, Eve cannot inject her keys anymore. '
                'Reset the application to try the MITM attack at the beginning.'
            )
        }), 400
    
    # Generate Eve's key pair (she uses the SAME key pair for both directions)
    eve_private, eve_public = crypto_manager.generate_rsa_keypair()
    
    mitm_mode['active'] = True
    mitm_mode['eve_keys'] = {
        'private_key': crypto_manager.serialize_private_key(eve_private),
        'public_key': crypto_manager.serialize_public_key(eve_public)
    }
    # Store original keys for reference
    mitm_mode['alice_original_public'] = user_keys['alice']['public_key']
    mitm_mode['bob_original_public'] = user_keys['bob']['public_key']
    
    return jsonify({
        'success': True,
        'message': 'MITM attack enabled at KEY EXCHANGE PHASE!',
        'attack_description': (
            'Eve has intercepted the key exchange. She now sits between Alice and Bob:\n'
            '• Alice thinks she has Bob\'s key → Actually Eve\'s key\n'
            '• Bob thinks he has Alice\'s key → Actually Eve\'s key\n'
            'Eve can now:\n'
            '• Decrypt ALL messages from both directions\n'
            '• Modify messages before forwarding\n'
            '• Sign messages that Bob will accept (he\'ll verify with Eve\'s key!)'
        ),
        'eve_public_key_preview': mitm_mode['eve_keys']['public_key'][:100] + '...',
        'real_alice_key_preview': user_keys['alice']['public_key'][:100] + '...',
        'real_bob_key_preview': user_keys['bob']['public_key'][:100] + '...',
        'explanation': (
            'This is a classic Man-in-the-Middle attack on the key exchange phase. '
            'Digital signatures ALONE cannot prevent this because Bob will verify signatures '
            'using Eve\'s public key (which he thinks is Alice\'s). Eve\'s signatures will pass! '
            'The REAL defense is DIGITAL CERTIFICATES from a trusted Certificate Authority (CA).'
        ),
        'why_signatures_fail': (
            'Digital signatures only prove "signed by the private key holder." '
            'They do NOT prove "this public key belongs to Alice." '
            'Since Bob has Eve\'s key, Eve can sign and Bob will accept.'
        ),
        'real_defense': 'Digital Certificates from a trusted Certificate Authority (CA)'
    })


@app.route('/api/attack/mitm/disable', methods=['POST'])
def disable_mitm():
    """Disable MITM attack and restore legitimate keys."""
    global mitm_mode
    
    mitm_mode['active'] = False
    mitm_mode['eve_keys'] = None
    mitm_mode['intercepted'] = {}
    mitm_mode['alice_original_public'] = None
    mitm_mode['bob_original_public'] = None
    
    return jsonify({
        'success': True,
        'message': 'MITM attack disabled. Legitimate keys restored for both Alice and Bob.'
    })


@app.route('/api/attack/mitm/status', methods=['GET'])
def mitm_status():
    """Get current MITM attack status and explanation."""
    return jsonify({
        'mitm_active': mitm_mode['active'],
        'session_established': session_established,
        'can_enable_mitm': not session_established,
        'intercepted_count': len(mitm_mode['intercepted']),
        'explanation': {
            'attack_phase': 'KEY_EXCHANGE' if not session_established else 'SESSION_ACTIVE',
            'description': (
                'MITM attack works at the KEY EXCHANGE PHASE:\n\n'
                '1. Before any messages are sent, Eve intercepts the key exchange\n'
                '2. Eve gives her public key to BOTH Alice and Bob\n'
                '   - Alice thinks she has Bob\'s key (but it\'s Eve\'s)\n'
                '   - Bob thinks he has Alice\'s key (but it\'s Eve\'s)\n'
                '3. When Alice sends a message to "Bob":\n'
                '   - She encrypts with Eve\'s key\n'
                '   - Eve decrypts, reads (and can modify!) the message\n'
                '   - Eve re-encrypts with Bob\'s REAL key\n'
                '   - Eve SIGNS with her own key (Bob will accept it!)\n'
                '   - Eve forwards to Bob\n'
                '4. Bob receives the message, signature verifies, completely fooled!\n\n'
                '⚠️ IMPORTANT: Digital signatures ALONE do NOT prevent this!\n'
                'Bob verifies with Eve\'s key (thinking it\'s Alice\'s), so Eve\'s\n'
                'signatures pass verification.\n\n'
                '✓ REAL DEFENSE: DIGITAL CERTIFICATES\n'
                'A Certificate Authority (CA) signs certificates binding identities\n'
                'to public keys. Eve cannot forge CA-signed certificates.\n'
                'This is how HTTPS/TLS protects against MITM attacks.'
            ),
            'current_status': (
                'MITM is ACTIVE. Eve sits between Alice and Bob. She can read AND modify all messages!'
                if mitm_mode['active'] else
                ('Session already started. MITM cannot be enabled mid-session.'
                 if session_established else
                 'Ready for MITM attack. Enable it before sending any messages!')
            ),
            'why_signatures_dont_help': (
                'Digital signatures prove "signed by private key holder" but NOT '
                '"this public key belongs to Alice." Without certificates, Bob cannot '
                'distinguish Eve\'s key from Alice\'s key.'
            ),
            'real_defense': (
                'DIGITAL CERTIFICATES from a trusted Certificate Authority (CA). '
                'The CA signs a certificate stating "This public key belongs to Alice." '
                'Eve cannot forge this without the CA\'s private key. '
                'This is the foundation of HTTPS/TLS security.'
            )
        }
    })


@app.route('/api/attack/mitm/decrypt', methods=['POST'])
@rate_limit_check
def mitm_decrypt():
    """
    Eve decrypts intercepted message using her private key.
    
    Since Eve gave her public key to Alice (who thinks it's Bob's),
    Alice encrypted the session key with Eve's public key.
    Eve can decrypt it with her private key!
    """
    try:
        if not mitm_mode['active'] or not mitm_mode['eve_keys']:
            return jsonify({
                'success': False,
                'error': 'MITM mode is not active. Enable it first at the key exchange phase!'
            }), 400
        
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({'success': False, 'error': 'No payload provided'}), 400
        
        eve_private_key = crypto_manager.load_private_key(mitm_mode['eve_keys']['private_key'])
        
        logs = []
        logs.append("=" * 50)
        logs.append("EVE INTERCEPTS AND DECRYPTS THE MESSAGE")
        logs.append("=" * 50)
        logs.append("[EVE] I intercepted a message from Alice to Bob!")
        logs.append("[EVE] Alice encrypted it with MY public key (she thinks it's Bob's)")
        logs.append("[EVE] Decrypting with my private key...")
        
        try:
            import base64
            
            encrypted_session_key = base64.b64decode(payload['encrypted_session_key'])
            iv = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            
            session_key = crypto_manager.rsa_decrypt(encrypted_session_key, eve_private_key)
            logs.append(f"[EVE] ✓ Decrypted session key: {session_key.hex()}")
            
            plaintext_bytes = crypto_manager.aes_decrypt(ciphertext, session_key, iv)
            plaintext = plaintext_bytes.decode('utf-8')
            logs.append(f"[EVE] ✓ Decrypted message: \"{plaintext}\"")
            logs.append("")
            logs.append("[EVE] 😈 I can read everything Alice sends to Bob!")
            
            intercept_id = f"intercept_{int(time.time() * 1000)}"
            mitm_mode['intercepted'][intercept_id] = {
                'plaintext': plaintext,
                'original_payload': payload,
                'session_key': session_key.hex()
            }
            
            return jsonify({
                'success': True,
                'attack_type': 'MITM_DECRYPT',
                'intercepted_message': plaintext,
                'session_key': session_key.hex(),
                'intercept_id': intercept_id,
                'logs': logs,
                'explanation': (
                    'SUCCESS! Eve decrypted Alice\'s message because Alice unknowingly '
                    'encrypted it with Eve\'s public key during the key exchange. '
                    'Use /api/attack/mitm/relay to forward it to Bob (re-encrypted with Bob\'s real key).'
                )
            })
            
        except Exception as e:
            logs.append(f"[EVE] ✗ Decryption failed: {str(e)}")
            logs.append("[EVE] The message was not encrypted with my key.")
            logs.append("[EVE] This could mean MITM wasn't active during key exchange.")
            return jsonify({
                'success': False,
                'error': f'Eve\'s decryption failed: {str(e)}',
                'logs': logs,
                'explanation': 'The message was not encrypted with Eve\'s key. Was MITM active during key exchange?'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/mitm/relay', methods=['POST'])
@rate_limit_check
def mitm_relay():
    """
    Eve re-encrypts and forwards the message to Bob.
    
    CRITICAL INSIGHT: Since Bob has EVE's public key (thinking it's Alice's),
    Eve can sign messages with HER private key and Bob will accept them!
    
    Digital signatures ALONE cannot prevent MITM at key exchange phase.
    Digital CERTIFICATES are needed for that.
    """
    try:
        if not mitm_mode['active'] or not mitm_mode['eve_keys']:
            return jsonify({
                'success': False,
                'error': 'MITM mode is not active. Enable it first!'
            }), 400
        
        data = request.get_json()
        intercept_id = data.get('intercept_id')
        modify_message = data.get('modify_message', None)  # Optional: Eve can modify the message
        
        if not intercept_id or intercept_id not in mitm_mode['intercepted']:
            if not mitm_mode['intercepted']:
                return jsonify({
                    'success': False,
                    'error': 'No intercepted messages. Use /api/attack/mitm/decrypt first!'
                }), 400
            intercept_id = list(mitm_mode['intercepted'].keys())[-1]
        
        intercepted = mitm_mode['intercepted'][intercept_id]
        plaintext = modify_message if modify_message else intercepted['plaintext']
        
        logs = []
        logs.append("=" * 50)
        logs.append("EVE RELAYS MESSAGE TO BOB")
        logs.append("=" * 50)
        
        if modify_message:
            logs.append(f"[EVE] Original message: \"{intercepted['plaintext']}\"")
            logs.append(f"[EVE] 😈 Modifying to: \"{plaintext}\"")
        else:
            logs.append(f"[EVE] Forwarding message: \"{plaintext}\"")
        
        logs.append("[EVE] Re-encrypting with Bob's REAL public key...")
        
        import base64
        
        # Use Bob's REAL public key (the one Eve kept hidden from Alice)
        bob_public_key = crypto_manager.load_public_key(user_keys['bob']['public_key'])
        eve_private_key = crypto_manager.load_private_key(mitm_mode['eve_keys']['private_key'])
        
        new_session_key = crypto_manager.generate_session_key()
        new_iv = crypto_manager.generate_iv()
        logs.append(f"[EVE] Generated new session key: {new_session_key.hex()[:32]}...")
        
        plaintext_bytes = plaintext.encode('utf-8')
        new_ciphertext = crypto_manager.aes_encrypt(plaintext_bytes, new_session_key, new_iv)
        logs.append("[EVE] ✓ Message encrypted with AES")
        
        new_encrypted_session_key = crypto_manager.rsa_encrypt(new_session_key, bob_public_key)
        logs.append("[EVE] ✓ Session key encrypted with Bob's REAL public key")
        
        # KEY INSIGHT: Eve signs with HER private key
        # Bob will verify with what he thinks is "Alice's public key" (actually Eve's)
        # So the signature will PASS!
        logs.append("")
        logs.append("[EVE] 😈 Now for the clever part...")
        logs.append("[EVE] Bob thinks he has Alice's public key, but he has MINE!")
        logs.append("[EVE] So I'll sign with MY private key...")
        logs.append("[EVE] Bob will verify with MY public key (thinking it's Alice's)...")
        logs.append("[EVE] The signature will PASS! Bob won't detect anything!")
        
        eve_signature = crypto_manager.sign_message(new_ciphertext, eve_private_key)
        logs.append(f"[EVE] ✓ Signed with Eve's private key: {eve_signature.hex()[:32]}...")
        
        relayed_payload = {
            'encrypted_session_key': base64.b64encode(new_encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(new_iv).decode('utf-8'),
            'ciphertext': base64.b64encode(new_ciphertext).decode('utf-8'),
            'signature': base64.b64encode(eve_signature).decode('utf-8'),  # Eve's valid signature!
            'timestamp': time.time()
        }
        
        payload_id = f"relay_{int(time.time() * 1000)}"
        captured_payloads[payload_id] = relayed_payload
        
        logs.append("")
        logs.append("=" * 50)
        logs.append("WHY THE ATTACK SUCCEEDS")
        logs.append("=" * 50)
        logs.append("[INFO] Bob has Eve's public key (thinking it's Alice's)")
        logs.append("[INFO] Eve signs with her private key")
        logs.append("[INFO] Bob verifies: signature matches Eve's public key ✓")
        logs.append("[INFO] Bob thinks: 'Signature valid, this is from Alice!'")
        logs.append("[INFO] ATTACK SUCCEEDS! Bob is completely fooled!")
        logs.append("")
        logs.append("=" * 50)
        logs.append("WHY DIGITAL SIGNATURES ALONE DON'T HELP")
        logs.append("=" * 50)
        logs.append("[INFO] Digital signatures verify: 'signed by holder of private key'")
        logs.append("[INFO] But Bob is using the WRONG public key to verify!")
        logs.append("[INFO] The signature system works perfectly...")
        logs.append("[INFO] ...but Bob's trust assumption is broken.")
        logs.append("")
        logs.append("=" * 50)
        logs.append("THE REAL DEFENSE: DIGITAL CERTIFICATES")
        logs.append("=" * 50)
        logs.append("[INFO] A Certificate Authority (CA) signs certificates binding")
        logs.append("[INFO] identities to public keys.")
        logs.append("[INFO] Bob would ask: 'Show me a CA-signed certificate for Alice'")
        logs.append("[INFO] Eve cannot forge this because she doesn't have CA's private key!")
        logs.append("[INFO] This is how HTTPS/TLS protects against MITM attacks.")
        
        return jsonify({
            'success': True,
            'attack_type': 'MITM_RELAY',
            'attack_succeeded': True,
            'relayed_message': plaintext,
            'original_message': intercepted['plaintext'],
            'was_modified': modify_message is not None,
            'payload_id': payload_id,
            'payload': relayed_payload,
            'logs': logs,
            'explanation': (
                'THE MITM ATTACK SUCCEEDS! Eve can read and modify messages freely. '
                'Digital signatures DO NOT prevent this attack because Bob has the wrong '
                'public key. Bob verifies Eve\'s signature with Eve\'s public key (which he '
                'thinks is Alice\'s), so verification passes. '
                'DIGITAL CERTIFICATES are required to prevent MITM at key exchange.'
            ),
            'why_signatures_fail': (
                'Digital signatures only prove "this was signed by the private key holder." '
                'They do NOT prove "this public key belongs to Alice." '
                'Without certificates, Bob cannot distinguish Eve\'s key from Alice\'s key.'
            ),
            'real_defense': (
                'DIGITAL CERTIFICATES: A trusted Certificate Authority (CA) signs a certificate '
                'stating "This public key belongs to Alice." Eve cannot forge this certificate '
                'because she doesn\'t have the CA\'s private key. This is how HTTPS works - '
                'websites present CA-signed certificates to prove their identity.'
            )
        })
        
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@app.route('/api/attack/dos/status', methods=['GET'])
def dos_status():
    """Get current DoS defense status."""
    return jsonify({
        'rate_limiter_stats': rate_limiter.get_stats(),
        'your_ip': request.remote_addr or '127.0.0.1',
        'explanation': f'Rate limit: {rate_limiter.rate_limit} requests per {rate_limiter.rate_window}s.'
    })


@app.route('/api/attack/dos/reset', methods=['POST'])
def dos_reset():
    """Reset rate limiter state."""
    rate_limiter.reset()
    return jsonify({'success': True, 'message': 'Rate limiter reset. All IPs unblocked.'})


@app.route('/api/attack/dos/test', methods=['POST'])
@rate_limit_check
def dos_test_endpoint():
    """Test endpoint for DoS attack simulation."""
    ip = request.remote_addr or '127.0.0.1'
    remaining = rate_limiter.rate_limit - len(rate_limiter.request_log.get(ip, []))
    
    return jsonify({
        'success': True,
        'message': 'Request successful',
        'your_ip': ip,
        'requests_remaining': remaining,
        'rate_limit_stats': rate_limiter.get_stats()
    })


@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Get all exchanged messages."""
    return jsonify({
        'messages': message_store,
        'captured_payloads': list(captured_payloads.keys())
    })


@app.route('/api/reset', methods=['POST'])
def reset_state():
    """Reset all application state - allows MITM attack to be tested again."""
    global message_store, used_nonces, captured_payloads, mitm_mode, session_established
    
    message_store = []
    used_nonces = set()
    captured_payloads = {}
    session_established = False  # Reset so MITM can be enabled at key exchange again
    mitm_mode = {
        'active': False,
        'eve_keys': None,
        'intercepted': {},
        'alice_original_public': None,
        'bob_original_public': None
    }
    rate_limiter.reset()
    initialize_keys()
    
    return jsonify({
        'success': True,
        'message': 'All state reset. New keys generated. You can now enable MITM at the key exchange phase.'
    })


@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'attack_detected': 'DOS_ATTACK',
        'message': str(e)
    }), 429


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': str(e)
    }), 500


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("SECURE MESSAGING APPLICATION")
    print("ICS344 Cryptography Project")
    print("=" * 70)
    print("\n[INFO] Starting Flask server...")
    print("[INFO] Access the dashboard at: http://127.0.0.1:5000")
    print("[INFO] Rate limiting enabled: 10 requests/60s per IP")
    print("\n" + "=" * 70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
