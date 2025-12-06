"""
Secure Messaging Application
Flask-based web application demonstrating cryptographic principles:
- AES-CBC encryption with PKCS#7 padding for confidentiality
- RSA-2048 digital signatures for integrity and authentication
- Defense against Replay, Message Injection, MITM, and DoS attacks
"""

from flask import Flask, render_template, request, jsonify, session
import json
import time
import os
from functools import wraps

from crypto_utils import (
    AESCipher, RSAKeyManager, RSASignature, 
    SecureMessage, AttackSimulator, RateLimiter
)

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Session encryption key

# Request logging for security audit
@app.before_request
def log_request_info():
    """Log incoming requests for security auditing"""
    # Skip logging for static files and frequent endpoints
    if request.path.startswith('/static') or request.path == '/api/logs' or request.path == '/api/rate-limit/status':
        return
    
    # Log API requests
    if request.path.startswith('/api/'):
        pass  # Individual endpoints handle their own detailed logging

# ==================== Global State ====================

# Store users and their keys (in production, use a database)
users = {}

# Message storage
messages = []

# Secure message handler
secure_message_handler = SecureMessage()

# Rate limiter for DoS protection
rate_limiter = RateLimiter(max_requests=20, window_seconds=60)

# Action logs
action_logs = []

def add_log(action: str, user: str = None, details: str = None, level: str = "info", 
            metadata: dict = None):
    """Add an entry to the action log with terminal-style formatting"""
    
    # Generate unique log ID
    log_id = f"LOG-{len(action_logs)+1:04d}"
    
    # Get process info
    import socket
    hostname = socket.gethostname()
    
    log_entry = {
        'id': log_id,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'unix_time': time.time(),
        'action': action,
        'user': user if user else 'SYSTEM',
        'details': details,
        'level': level,  # info, warning, error, success, attack, crypto, network
        'metadata': metadata or {},
        'hostname': hostname,
        'pid': os.getpid()
    }
    action_logs.append(log_entry)
    # Keep only last 200 logs
    if len(action_logs) > 200:
        action_logs.pop(0)
    return log_entry


# ==================== Rate Limiting Decorator ====================

def rate_limit_check(f):
    """Decorator to check rate limits"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_id = request.remote_addr or 'unknown'
        allowed, remaining, reset_time = rate_limiter.is_allowed(client_id)
        
        if not allowed:
            add_log("DoS Protection Triggered", client_id, 
                   f"Rate limit exceeded. Reset in {reset_time}s", "attack",
                   metadata={
                       'attack_type': 'DoS/Rate Limit Violation',
                       'client_ip': client_id,
                       'reset_seconds': reset_time,
                       'max_requests': rate_limiter.max_requests,
                       'window': rate_limiter.window_seconds
                   })
            return jsonify({
                'success': False,
                'error': f'Rate limit exceeded. Try again in {reset_time} seconds.',
                'attack_detected': 'DoS',
                'remaining_requests': 0
            }), 429
        
        response = f(*args, **kwargs)
        return response
    return decorated_function


# ==================== Routes ====================

@app.route('/')
def index():
    """Main application page"""
    return render_template('index.html')


@app.route('/api/generate-keys', methods=['POST'])
@rate_limit_check
def generate_keys():
    """Generate RSA key pair for a user"""
    data = request.get_json()
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    
    if username in users:
        return jsonify({'success': False, 'error': 'User already exists'}), 400
    
    # Generate RSA-2048 key pair
    rsa_manager = RSAKeyManager(key_size=2048)
    keys = rsa_manager.generate_keys()
    
    # Store user
    users[username] = {
        'private_key': keys['private_key'],
        'public_key': keys['public_key'],
        'created_at': time.time()
    }
    
    add_log("Key Generation", username, "RSA-2048 key pair generated", "crypto",
           metadata={
               'algorithm': 'RSA',
               'key_size': 2048,
               'public_key_fingerprint': keys['public_key'][27:55] + '...',
               'operation': 'KEY_PAIR_GENERATION'
           })
    
    return jsonify({
        'success': True,
        'username': username,
        'public_key': keys['public_key'],
        'private_key': keys['private_key'],
        'message': f'RSA-2048 key pair generated for {username}'
    })


@app.route('/api/users', methods=['GET'])
def get_users():
    """Get list of registered users with their public keys"""
    user_list = []
    for username, data in users.items():
        user_list.append({
            'username': username,
            'public_key': data['public_key']
        })
    return jsonify({'success': True, 'users': user_list})


@app.route('/api/send-message', methods=['POST'])
@rate_limit_check
def send_message():
    """Send an encrypted and signed message"""
    data = request.get_json()
    
    sender = data.get('sender', '').strip()
    recipient = data.get('recipient', '').strip()
    plaintext = data.get('message', '').strip()
    
    # Validation
    if not all([sender, recipient, plaintext]):
        return jsonify({'success': False, 'error': 'Sender, recipient, and message are required'}), 400
    
    if sender not in users:
        return jsonify({'success': False, 'error': f'Sender "{sender}" not registered'}), 400
    
    if recipient not in users:
        return jsonify({'success': False, 'error': f'Recipient "{recipient}" not registered'}), 400
    
    try:
        # Create secure message
        secure_msg = secure_message_handler.create_secure_message(
            plaintext=plaintext,
            sender_private_key=users[sender]['private_key'],
            recipient_public_key=users[recipient]['public_key']
        )
        
        # Store message
        message_record = {
            'id': len(messages) + 1,
            'sender': sender,
            'recipient': recipient,
            'secure_message': secure_msg,
            'timestamp': time.time(),
            'status': 'sent'
        }
        messages.append(message_record)
        
        add_log("Message Sent", sender, 
               f"Encrypted message to {recipient} (ID: {message_record['id']})", "crypto",
               metadata={
                   'message_id': message_record['id'],
                   'recipient': recipient,
                   'encryption': 'AES-256-CBC',
                   'key_exchange': 'RSA-2048-OAEP',
                   'signature': 'RSA-SHA256',
                   'iv': secure_msg['iv'][:16] + '...',
                   'nonce': secure_msg['nonce'],
                   'ciphertext_length': len(secure_msg['ciphertext']),
                   'operation': 'ENCRYPT_AND_SIGN'
               })
        
        return jsonify({
            'success': True,
            'message_id': message_record['id'],
            'encrypted_data': {
                'iv': secure_msg['iv'],
                'ciphertext': secure_msg['ciphertext'],
                'encrypted_aes_key': secure_msg['encrypted_aes_key'][:50] + '...',
                'signature': secure_msg['signature'][:50] + '...',
                'nonce': secure_msg['nonce'],
                'timestamp': secure_msg['timestamp']
            },
            'details': {
                'encryption': 'AES-256-CBC with PKCS#7 padding',
                'key_exchange': 'RSA-2048 OAEP',
                'signature': 'RSA-2048 with SHA-256'
            }
        })
        
    except Exception as e:
        add_log("Encryption Error", sender, str(e), "error",
               metadata={
                   'operation': 'ENCRYPT_FAILURE',
                   'sender': sender,
                   'recipient': recipient,
                   'error_type': type(e).__name__,
                   'error_message': str(e)
               })
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/receive-message', methods=['POST'])
@rate_limit_check
def receive_message():
    """Receive and verify a message"""
    data = request.get_json()
    
    message_id = data.get('message_id')
    recipient = data.get('recipient', '').strip()
    
    if not message_id or not recipient:
        return jsonify({'success': False, 'error': 'Message ID and recipient are required'}), 400
    
    if recipient not in users:
        return jsonify({'success': False, 'error': f'Recipient "{recipient}" not registered'}), 400
    
    # Find message
    message_record = None
    for msg in messages:
        if msg['id'] == message_id:
            message_record = msg
            break
    
    if not message_record:
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    if message_record['recipient'] != recipient:
        add_log("Unauthorized Access Attempt", recipient, 
               f"Attempted to read message {message_id} intended for {message_record['recipient']}", "warning",
               metadata={
                   'attempted_action': 'READ_MESSAGE',
                   'message_id': message_id,
                   'actual_recipient': message_record['recipient'],
                   'unauthorized_user': recipient,
                   'client_ip': request.remote_addr,
                   'status_code': 403
               })
        return jsonify({'success': False, 'error': 'Not authorized to read this message'}), 403
    
    try:
        # Verify and decrypt
        result = secure_message_handler.verify_and_decrypt(
            message=message_record['secure_message'],
            sender_public_key=users[message_record['sender']]['public_key'],
            recipient_private_key=users[recipient]['private_key']
        )
        
        if result['success']:
            add_log("Message Received", recipient, 
                   f"Decrypted message {message_id} from {message_record['sender']}", "success",
                   metadata={
                       'message_id': message_id,
                       'sender': message_record['sender'],
                       'signature_valid': result['security_checks']['signature_valid'],
                       'replay_check': result['security_checks']['replay_check_passed'],
                       'timestamp_valid': result['security_checks']['timestamp_valid'],
                       'operation': 'VERIFY_AND_DECRYPT'
                   })
        else:
            log_level = "attack" if result['errors'] else "warning"
            add_log("Verification Failed", recipient, 
                   '; '.join(result['errors']), log_level,
                   metadata={
                       'message_id': message_id,
                       'sender': message_record['sender'],
                       'security_checks': result['security_checks'],
                       'errors': result['errors'],
                       'operation': 'VERIFICATION_FAILURE'
                   })
        
        return jsonify({
            'success': result['success'],
            'sender': message_record['sender'],
            'plaintext': result['plaintext'],
            'security_checks': result['security_checks'],
            'warnings': result['warnings'],
            'errors': result['errors']
        })
        
    except Exception as e:
        add_log("Decryption Error", recipient, str(e), "error",
               metadata={
                   'operation': 'DECRYPT_FAILURE',
                   'message_id': message_id,
                   'recipient': recipient,
                   'error_type': type(e).__name__,
                   'error_message': str(e)
               })
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/messages/<recipient>', methods=['GET'])
def get_messages(recipient):
    """Get all messages for a recipient"""
    if recipient not in users:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    user_messages = []
    for msg in messages:
        if msg['recipient'] == recipient:
            user_messages.append({
                'id': msg['id'],
                'sender': msg['sender'],
                'timestamp': msg['timestamp'],
                'status': msg['status']
            })
    
    return jsonify({'success': True, 'messages': user_messages})


# ==================== Attack Simulation Endpoints ====================

@app.route('/api/attack/replay', methods=['POST'])
@rate_limit_check
def simulate_replay():
    """Simulate a replay attack"""
    data = request.get_json()
    message_id = data.get('message_id')
    recipient = data.get('recipient', '').strip()
    
    if not message_id or not recipient:
        return jsonify({'success': False, 'error': 'Message ID and recipient required'}), 400
    
    # Find original message
    message_record = None
    for msg in messages:
        if msg['id'] == message_id:
            message_record = msg
            break
    
    if not message_record:
        return jsonify({'success': False, 'error': 'Original message not found'}), 404
    
    # Simulate replay attack
    replayed_message = AttackSimulator.simulate_replay_attack(message_record['secure_message'])
    
    add_log("Replay Attack Simulated", "ATTACKER", 
           f"Replaying message {message_id}", "attack",
           metadata={
               'attack_type': 'REPLAY_ATTACK',
               'target_message_id': message_id,
               'victim': recipient,
               'original_sender': message_record['sender'],
               'nonce': message_record['secure_message']['nonce'],
               'original_timestamp': message_record['secure_message']['timestamp'],
               'attack_vector': 'Captured message re-transmission'
           })
    
    # Try to verify replayed message
    result = secure_message_handler.verify_and_decrypt(
        message=replayed_message,
        sender_public_key=users[message_record['sender']]['public_key'],
        recipient_private_key=users[recipient]['private_key']
    )
    
    return jsonify({
        'attack_type': 'Replay Attack',
        'description': 'Attacker captured and re-sent a valid encrypted message',
        'defense_mechanism': 'Nonce tracking - each message has a unique nonce that can only be used once',
        'attack_detected': not result['security_checks']['replay_check_passed'],
        'result': result
    })


@app.route('/api/attack/injection', methods=['POST'])
@rate_limit_check
def simulate_injection():
    """Simulate a message injection/tampering attack"""
    data = request.get_json()
    message_id = data.get('message_id')
    recipient = data.get('recipient', '').strip()
    
    if not message_id or not recipient:
        return jsonify({'success': False, 'error': 'Message ID and recipient required'}), 400
    
    # Find original message
    message_record = None
    for msg in messages:
        if msg['id'] == message_id:
            message_record = msg
            break
    
    if not message_record:
        return jsonify({'success': False, 'error': 'Original message not found'}), 404
    
    # Simulate injection attack
    tampered_message = AttackSimulator.simulate_message_injection(message_record['secure_message'])
    
    add_log("Message Injection Simulated", "ATTACKER", 
           f"Tampering with message {message_id} in transit", "attack",
           metadata={
               'attack_type': 'MESSAGE_INJECTION',
               'target_message_id': message_id,
               'victim': recipient,
               'scenario': 'Attacker intercepts message BEFORE delivery',
               'original_ciphertext': message_record['secure_message']['ciphertext'][:20] + '...',
               'tampered_ciphertext': tampered_message['ciphertext'][:20] + '...',
               'original_nonce': message_record['secure_message']['nonce'][:16] + '...',
               'attack_nonce': tampered_message['nonce'][:16] + '...',
               'bytes_modified': '16-32 (bit flip attack)',
               'attack_vector': 'Ciphertext modification in transit',
               'expected_defense': 'Signature verification failure'
           })
    
    # Try to verify tampered message
    result = secure_message_handler.verify_and_decrypt(
        message=tampered_message,
        sender_public_key=users[message_record['sender']]['public_key'],
        recipient_private_key=users[recipient]['private_key']
    )
    
    return jsonify({
        'attack_type': 'Message Injection / Ciphertext Tampering',
        'description': 'Attacker modified the encrypted ciphertext in transit',
        'defense_mechanism': 'RSA Digital Signature - any modification invalidates the signature',
        'attack_detected': not result['security_checks']['signature_valid'],
        'original_ciphertext': message_record['secure_message']['ciphertext'][:50] + '...',
        'tampered_ciphertext': tampered_message['ciphertext'][:50] + '...',
        'result': result
    })


@app.route('/api/attack/mitm', methods=['POST'])
@rate_limit_check
def simulate_mitm():
    """Simulate a Man-in-the-Middle attack"""
    data = request.get_json()
    message_id = data.get('message_id')
    recipient = data.get('recipient', '').strip()
    
    if not message_id or not recipient:
        return jsonify({'success': False, 'error': 'Message ID and recipient required'}), 400
    
    # Find original message
    message_record = None
    for msg in messages:
        if msg['id'] == message_id:
            message_record = msg
            break
    
    if not message_record:
        return jsonify({'success': False, 'error': 'Original message not found'}), 404
    
    # Generate attacker's key pair
    attacker_keys = RSAKeyManager(key_size=2048)
    attacker_keys.generate_keys()
    
    # Simulate MITM attack
    mitm_message = AttackSimulator.simulate_mitm_attack(
        message_record['secure_message'],
        attacker_keys.private_key.export_key().decode('utf-8')
    )
    
    add_log("MITM Attack Simulated", "ATTACKER", 
           f"Intercepting and re-signing message {message_id} in transit", "attack",
           metadata={
               'attack_type': 'MAN_IN_THE_MIDDLE',
               'target_message_id': message_id,
               'victim': recipient,
               'impersonated_sender': message_record['sender'],
               'scenario': 'Attacker intercepts message BEFORE delivery',
               'attacker_key_size': 2048,
               'original_nonce': message_record['secure_message']['nonce'][:16] + '...',
               'attack_nonce': mitm_message['nonce'][:16] + '...',
               'original_signature': message_record['secure_message']['signature'][:30] + '...',
               'forged_signature': mitm_message['signature'][:30] + '...',
               'attack_vector': 'Signature forgery with attacker private key',
               'expected_defense': 'Signature verification failure (wrong public key)'
           })
    
    # Try to verify MITM message (should fail because signature doesn't match sender's public key)
    result = secure_message_handler.verify_and_decrypt(
        message=mitm_message,
        sender_public_key=users[message_record['sender']]['public_key'],
        recipient_private_key=users[recipient]['private_key']
    )
    
    return jsonify({
        'attack_type': 'Man-in-the-Middle (MITM)',
        'description': 'Attacker intercepted the message and re-signed it with their own private key',
        'defense_mechanism': 'RSA Digital Signature verification with trusted public key - signature must match known sender',
        'attack_detected': not result['security_checks']['signature_valid'],
        'explanation': 'The attacker\'s signature cannot be verified with the real sender\'s public key',
        'result': result
    })


@app.route('/api/attack/dos', methods=['POST'])
def simulate_dos():
    """Simulate a Denial of Service attack"""
    data = request.get_json()
    num_requests = min(data.get('num_requests', 50), 100)  # Cap at 100
    
    add_log("DoS Attack Simulated", "ATTACKER", 
           f"Flooding with {num_requests} requests", "attack",
           metadata={
               'attack_type': 'DENIAL_OF_SERVICE',
               'flood_requests': num_requests,
               'rate_limit_threshold': rate_limiter.max_requests,
               'window_seconds': rate_limiter.window_seconds,
               'attack_vector': 'Request flooding / Resource exhaustion'
           })
    
    # Simulate rapid requests
    attack_results = []
    test_client_id = f"attacker_{time.time()}"
    
    for i in range(num_requests):
        allowed, remaining, reset_time = rate_limiter.is_allowed(test_client_id)
        attack_results.append({
            'request_num': i + 1,
            'allowed': allowed,
            'remaining': remaining
        })
        if not allowed:
            blocked_at = i + 1
            break
    else:
        blocked_at = None
    
    return jsonify({
        'attack_type': 'Denial of Service (DoS)',
        'description': f'Attacker attempted to flood the server with {num_requests} rapid requests',
        'defense_mechanism': 'Rate limiting - max 20 requests per 60 seconds per IP',
        'attack_mitigated': blocked_at is not None,
        'blocked_at_request': blocked_at,
        'rate_limit_config': {
            'max_requests': rate_limiter.max_requests,
            'window_seconds': rate_limiter.window_seconds
        },
        'sample_results': attack_results[:25]  # Show first 25 results
    })


# ==================== Utility Endpoints ====================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get action logs"""
    return jsonify({
        'success': True,
        'logs': action_logs[-50:]  # Last 50 logs
    })


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear action logs"""
    action_logs.clear()
    add_log("Logs Cleared", None, "All logs cleared", "info")
    return jsonify({'success': True, 'message': 'Logs cleared'})


@app.route('/api/rate-limit/status', methods=['GET'])
def rate_limit_status():
    """Get current rate limit status"""
    client_id = request.remote_addr or 'unknown'
    status = rate_limiter.get_status(client_id)
    return jsonify({'success': True, **status})


@app.route('/api/reset', methods=['POST'])
def reset_system():
    """Reset the entire system (for demo purposes)"""
    global users, messages, action_logs
    users.clear()
    messages.clear()
    action_logs.clear()
    secure_message_handler.clear_old_nonces()
    
    add_log("System Reset", "ADMIN", "Full system reset executed", "warning",
           metadata={
               'operation': 'SYSTEM_RESET',
               'users_cleared': True,
               'messages_cleared': True,
               'logs_cleared': True,
               'nonces_cleared': True,
               'client_ip': request.remote_addr
           })
    
    return jsonify({'success': True, 'message': 'System reset complete'})


@app.route('/api/demo/setup', methods=['POST'])
def setup_demo():
    """Quick setup for demonstration"""
    # Create two demo users
    demo_users = ['Alice', 'Bob']
    created = []
    
    for username in demo_users:
        if username not in users:
            rsa_manager = RSAKeyManager(key_size=2048)
            keys = rsa_manager.generate_keys()
            users[username] = {
                'private_key': keys['private_key'],
                'public_key': keys['public_key'],
                'created_at': time.time()
            }
            created.append(username)
            add_log("Demo Setup", username, "Demo user created with RSA-2048 key pair", "info",
                   metadata={
                       'operation': 'DEMO_USER_CREATION',
                       'key_algorithm': 'RSA-2048',
                       'public_key_preview': keys['public_key'][27:60] + '...'
                   })
    
    return jsonify({
        'success': True,
        'message': f'Demo users created: {", ".join(created) if created else "Already exist"}',
        'users': [{'username': u, 'public_key': users[u]['public_key'][:100] + '...'} for u in demo_users]
    })


# ==================== Cryptographic Info Endpoint ====================

@app.route('/api/crypto-info', methods=['GET'])
def crypto_info():
    """Get information about cryptographic algorithms used"""
    return jsonify({
        'success': True,
        'algorithms': {
            'symmetric_encryption': {
                'name': 'AES-256-CBC',
                'key_size': '256 bits (32 bytes)',
                'block_size': '128 bits (16 bytes)',
                'padding': 'PKCS#7',
                'mode': 'CBC (Cipher Block Chaining)',
                'iv_size': '128 bits (16 bytes)',
                'description': 'Provides confidentiality for message content'
            },
            'asymmetric_encryption': {
                'name': 'RSA-2048',
                'key_size': '2048 bits',
                'padding': 'OAEP (Optimal Asymmetric Encryption Padding)',
                'usage': 'Encrypting AES session keys for secure key exchange',
                'description': 'Provides secure key distribution'
            },
            'digital_signature': {
                'name': 'RSA with SHA-256',
                'key_size': '2048 bits',
                'hash_algorithm': 'SHA-256',
                'signature_scheme': 'PKCS#1 v1.5',
                'description': 'Provides integrity and authentication'
            },
            'hash_function': {
                'name': 'SHA-256',
                'output_size': '256 bits (32 bytes)',
                'usage': 'Creating message digests for signing'
            }
        },
        'security_features': {
            'replay_protection': 'Nonce + Timestamp tracking',
            'integrity': 'Digital signatures on entire payload',
            'authentication': 'RSA signature verification with known public keys',
            'confidentiality': 'AES-256 encryption with random session keys',
            'dos_protection': 'Rate limiting (20 requests/minute)'
        }
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("   SECURE MESSAGING APPLICATION")
    print("   AES-CBC + RSA Digital Signatures")
    print("="*60)
    print("\n[*] Starting Flask server...")
    print("[*] Access the application at: http://127.0.0.1:5000")
    print("[*] Press Ctrl+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
