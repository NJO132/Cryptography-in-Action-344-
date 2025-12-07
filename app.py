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
mitm_mode = {'active': False, 'attacker_keys': None, 'intercepted': {}}


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
    """Get public keys. Returns attacker's key if MITM active."""
    if mitm_mode['active'] and mitm_mode['attacker_keys']:
        return jsonify({
            'alice_public_key': user_keys['alice']['public_key'],
            'bob_public_key': mitm_mode['attacker_keys']['public_key'],
            'mitm_active': True,
            'warning': 'MITM ATTACK ACTIVE - Eve has substituted Bob\'s key!'
        })
    
    return jsonify({
        'alice_public_key': user_keys['alice']['public_key'],
        'bob_public_key': user_keys['bob']['public_key'],
        'mitm_active': False
    })


@app.route('/api/send', methods=['POST'])
@rate_limit_check
def send_message():
    """Alice sends encrypted message to Bob."""
    try:
        data = request.get_json()
        plaintext = data.get('message', '')
        
        if not plaintext:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
        
        sender_private_key = crypto_manager.load_private_key(user_keys['alice']['private_key'])
        
        if mitm_mode['active'] and mitm_mode['attacker_keys']:
            receiver_public_key = crypto_manager.load_public_key(mitm_mode['attacker_keys']['public_key'])
            mitm_warning = "WARNING: Message encrypted with EVE'S public key (MITM active)!"
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
    """Bob receives and decrypts message."""
    global used_nonces
    
    try:
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({'success': False, 'error': 'No payload provided'}), 400
        
        receiver_private_key = crypto_manager.load_private_key(user_keys['bob']['private_key'])
        sender_public_key = crypto_manager.load_public_key(user_keys['alice']['public_key'])
        
        result = crypto_manager.process_received_payload(
            payload=payload,
            receiver_private_key=receiver_private_key,
            sender_public_key=sender_public_key,
            replay_window=60,
            used_nonces=used_nonces
        )
        
        for msg in message_store:
            if msg['payload'] == payload:
                msg['status'] = 'received' if result['success'] else 'rejected'
                msg['decrypted'] = result.get('plaintext', None)
                break
        
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
    """Enable MITM attack - substitute attacker's key for Bob's."""
    global mitm_mode
    
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
        'explanation': 'Eve has substituted her public key for Bob\'s in the directory.'
    })


@app.route('/api/attack/mitm/disable', methods=['POST'])
def disable_mitm():
    """Disable MITM attack and restore legitimate keys."""
    global mitm_mode
    
    mitm_mode['active'] = False
    mitm_mode['attacker_keys'] = None
    mitm_mode['intercepted'] = {}
    
    return jsonify({
        'success': True,
        'message': 'MITM attack disabled. Bob\'s legitimate key restored.'
    })


@app.route('/api/attack/mitm/decrypt', methods=['POST'])
@rate_limit_check
def mitm_decrypt():
    """Attacker decrypts intercepted message using their private key."""
    try:
        if not mitm_mode['active'] or not mitm_mode['attacker_keys']:
            return jsonify({
                'success': False,
                'error': 'MITM mode is not active. Enable it first!'
            }), 400
        
        data = request.get_json()
        payload = data.get('payload', {})
        
        if not payload:
            return jsonify({'success': False, 'error': 'No payload provided'}), 400
        
        attacker_private_key = crypto_manager.load_private_key(mitm_mode['attacker_keys']['private_key'])
        
        logs = []
        logs.append("[EVE] Attempting to decrypt intercepted message...")
        
        try:
            import base64
            
            encrypted_session_key = base64.b64decode(payload['encrypted_session_key'])
            iv = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            
            session_key = crypto_manager.rsa_decrypt(encrypted_session_key, attacker_private_key)
            logs.append(f"[EVE] ✓ Decrypted session key: {session_key.hex()}")
            
            plaintext_bytes = crypto_manager.aes_decrypt(ciphertext, session_key, iv)
            plaintext = plaintext_bytes.decode('utf-8')
            logs.append(f"[EVE] ✓ Decrypted message: {plaintext}")
            
            intercept_id = f"intercept_{int(time.time() * 1000)}"
            mitm_mode['intercepted'][intercept_id] = {
                'plaintext': plaintext,
                'original_payload': payload
            }
            
            return jsonify({
                'success': True,
                'attack_type': 'MITM_ATTACK',
                'intercepted_message': plaintext,
                'session_key': session_key.hex(),
                'intercept_id': intercept_id,
                'logs': logs,
                'explanation': 'SUCCESS! Eve decrypted the message. Use /api/attack/mitm/relay to forward it to Bob.'
            })
            
        except Exception as e:
            logs.append(f"[EVE] ✗ Decryption failed: {str(e)}")
            return jsonify({
                'success': False,
                'error': f'Eve\'s decryption failed: {str(e)}',
                'logs': logs,
                'explanation': 'The message was not encrypted with Eve\'s key.'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/attack/mitm/relay', methods=['POST'])
@rate_limit_check
def mitm_relay():
    """Eve re-encrypts and forwards the message to Bob."""
    try:
        if not mitm_mode['active'] or not mitm_mode['attacker_keys']:
            return jsonify({
                'success': False,
                'error': 'MITM mode is not active. Enable it first!'
            }), 400
        
        data = request.get_json()
        intercept_id = data.get('intercept_id')
        
        if not intercept_id or intercept_id not in mitm_mode['intercepted']:
            if not mitm_mode['intercepted']:
                return jsonify({
                    'success': False,
                    'error': 'No intercepted messages. Use /api/attack/mitm/decrypt first!'
                }), 400
            intercept_id = list(mitm_mode['intercepted'].keys())[-1]
        
        intercepted = mitm_mode['intercepted'][intercept_id]
        plaintext = intercepted['plaintext']
        
        logs = []
        logs.append("[EVE] Re-encrypting message for Bob...")
        
        import base64
        
        bob_public_key = crypto_manager.load_public_key(user_keys['bob']['public_key'])
        alice_private_key = crypto_manager.load_private_key(user_keys['alice']['private_key'])
        
        new_session_key = crypto_manager.generate_session_key()
        new_iv = crypto_manager.generate_iv()
        logs.append(f"[EVE] Generated new session key: {new_session_key.hex()[:32]}...")
        
        plaintext_bytes = plaintext.encode('utf-8')
        new_ciphertext = crypto_manager.aes_encrypt(plaintext_bytes, new_session_key, new_iv)
        logs.append("[EVE] ✓ Message re-encrypted with AES")
        
        new_encrypted_session_key = crypto_manager.rsa_encrypt(new_session_key, bob_public_key)
        logs.append("[EVE] ✓ Session key encrypted with Bob's REAL public key")
        
        original_payload = intercepted['original_payload']
        original_signature = base64.b64decode(original_payload['signature'])
        logs.append("[EVE] ✓ Keeping Alice's original signature")
        
        relayed_payload = {
            'encrypted_session_key': base64.b64encode(new_encrypted_session_key).decode('utf-8'),
            'iv': base64.b64encode(new_iv).decode('utf-8'),
            'ciphertext': base64.b64encode(new_ciphertext).decode('utf-8'),
            'signature': base64.b64encode(original_signature).decode('utf-8'),
            'timestamp': time.time()
        }
        
        logs.append("[EVE] ✓ Relayed payload created for Bob")
        logs.append(f"[EVE] Message being forwarded: \"{plaintext}\"")
        
        payload_id = f"relay_{int(time.time() * 1000)}"
        captured_payloads[payload_id] = relayed_payload
        
        logs.append("")
        logs.append("[WARNING] The signature was made over the ORIGINAL ciphertext!")
        logs.append("[WARNING] Bob's signature verification will FAIL because ciphertext changed!")
        
        return jsonify({
            'success': True,
            'attack_type': 'MITM_RELAY',
            'relayed_message': plaintext,
            'payload_id': payload_id,
            'payload': relayed_payload,
            'logs': logs,
            'explanation': 'Eve re-encrypted the message, but the signature won\'t match the new ciphertext. Bob will detect the tampering! This shows how digital signatures protect against MITM relay attacks.'
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
    """Reset all application state."""
    global message_store, used_nonces, captured_payloads, mitm_mode
    
    message_store = []
    used_nonces = set()
    captured_payloads = {}
    mitm_mode = {'active': False, 'attacker_keys': None, 'intercepted': {}}
    rate_limiter.reset()
    initialize_keys()
    
    return jsonify({'success': True, 'message': 'All state reset. New keys generated.'})


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
