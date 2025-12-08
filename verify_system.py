import requests
import time
import json
import sys

BASE_URL = "http://127.0.0.1:5000"

def print_pass(msg):
    print(f"\033[92m[PASS] {msg}\033[0m")

def print_fail(msg):
    print(f"\033[91m[FAIL] {msg}\033[0m")

def print_info(msg):
    print(f"\033[94m[INFO] {msg}\033[0m")

def reset_system():
    print_info("Resetting system state...")
    try:
        requests.post(f"{BASE_URL}/api/reset")
        requests.post(f"{BASE_URL}/api/attack/mitm/disable")
        requests.post(f"{BASE_URL}/api/attack/dos/reset")
    except Exception as e:
        print_fail(f"Could not reset system: {e}")
        sys.exit(1)

def test_normal_flow():
    print("\n--- Testing Normal Message Flow ---")
    
    # 1. Send Message
    msg = "Hello Bob, this is a test."
    resp = requests.post(f"{BASE_URL}/api/send", json={"message": msg})
    if resp.status_code != 200:
        print_fail(f"Send failed: {resp.text}")
        return None
    
    data = resp.json()
    if not data.get("success"):
        print_fail(f"Send API returned error: {data.get('error')}")
        return None
        
    payload = data.get("payload")
    print_pass("Alice sent encrypted message")
    
    # 2. Receive Message
    resp = requests.post(f"{BASE_URL}/api/receive", json={"payload": payload})
    if resp.status_code != 200:
        print_fail(f"Receive failed: {resp.text}")
        return None
        
    data = resp.json()
    if data.get("success") and data.get("plaintext") == msg:
        print_pass("Bob received and decrypted message correctly")
        return payload
    else:
        print_fail(f"Bob failed to decrypt: {data.get('error')}")
        return None

def test_replay_attack(valid_payload):
    print("\n--- Testing Replay Attack ---")
    if not valid_payload:
        print_fail("Skipping replay test due to missing payload")
        return

    # 1. Immediate Replay (Should be blocked by Nonce check if implemented, or allowed if only timestamp)
    # The current implementation checks nonce in `used_nonces` set.
    
    print_info("Attempting immediate replay...")
    resp = requests.post(f"{BASE_URL}/api/receive", json={"payload": valid_payload})
    data = resp.json()
    
    # Note: The app.py `receive_message` logic checks `used_nonces`.
    # If the first receive added it to used_nonces, the second should fail.
    
    if not data.get("success") and "Replay attack detected" in data.get("error", ""):
        print_pass("Immediate replay blocked (Nonce check)")
    else:
        print_fail(f"Immediate replay NOT blocked: {data}")

    # 2. Replay Endpoint Simulation
    # The /api/attack/replay endpoint simulates a replay.
    # It uses the last captured payload.
    
    print_info("Using /api/attack/replay endpoint...")
    resp = requests.post(f"{BASE_URL}/api/attack/replay", json={"payload_id": "latest"}) # payload_id logic in app.py handles missing ID
    data = resp.json()
    
    if data.get("defense_worked"):
         print_pass("Replay attack simulation correctly identified as blocked (or warned)")
    else:
         # If timestamp is fresh, it might say "WARNING: Replay attack succeeded!" which is technically correct behavior for the simulation if nonce check isn't enforced there or if it's a fresh simulation.
         # However, let's check the explanation.
         print_info(f"Replay simulation result: {data.get('explanation')}")

def test_injection_attack():
    print("\n--- Testing Message Injection Attack ---")
    
    resp = requests.post(f"{BASE_URL}/api/attack/injection", json={"message": "FAKE MESSAGE"})
    data = resp.json()
    
    if data.get("defense_worked"):
        print_pass("Injection attack blocked (Signature verification failed)")
    else:
        print_fail("Injection attack SUCCEEDED (Should be blocked!)")

def test_mitm_attack():
    print("\n--- Testing MITM Attack ---")
    
    # 1. Enable MITM
    resp = requests.post(f"{BASE_URL}/api/attack/mitm/enable")
    if resp.status_code != 200:
        print_fail("Could not enable MITM")
        return
    print_pass("MITM Enabled")
    
    # 2. Alice sends message (Encrypted with Eve's key)
    msg = "Secret for Bob"
    resp = requests.post(f"{BASE_URL}/api/send", json={"message": msg})
    payload = resp.json().get("payload")
    
    # 3. Eve Decrypts
    resp = requests.post(f"{BASE_URL}/api/attack/mitm/decrypt", json={"payload": payload})
    data = resp.json()
    
    if data.get("success") and data.get("intercepted_message") == msg:
        print_pass("Eve successfully intercepted and decrypted the message")
        intercept_id = data.get("intercept_id")
    else:
        print_fail("Eve failed to decrypt message")
        return

    # 4. Eve Relays (Re-encrypts for Bob)
    resp = requests.post(f"{BASE_URL}/api/attack/mitm/relay", json={"intercept_id": intercept_id})
    data = resp.json()
    relayed_payload = data.get("payload")
    
    if data.get("success"):
        print_pass("Eve relayed message")
    else:
        print_fail("Eve failed to relay")
        return
        
    # 5. Bob Receives Relayed Message (Should fail signature)
    # The relay attack keeps Alice's original signature but changes ciphertext.
    # Signature = Sign(Original_Ciphertext).
    # Bob receives New_Ciphertext. Verify(New_Ciphertext, Signature) -> Fail.
    
    resp = requests.post(f"{BASE_URL}/api/receive", json={"payload": relayed_payload})
    data = resp.json()
    
    if not data.get("success") and "Signature verification failed" in data.get("error", ""):
        print_pass("Bob rejected relayed message (Integrity check passed)")
    else:
        print_fail(f"Bob ACCEPTED relayed message (Integrity check FAILED): {data}")

    # Disable MITM
    requests.post(f"{BASE_URL}/api/attack/mitm/disable")

def test_dos_attack():
    print("\n--- Testing DoS Attack ---")
    
    # Reset limit first
    requests.post(f"{BASE_URL}/api/attack/dos/reset")
    
    # Send 15 requests (Limit is 10)
    blocked = False
    for i in range(15):
        resp = requests.post(f"{BASE_URL}/api/attack/dos/test")
        if resp.status_code == 429:
            blocked = True
            break
            
    if blocked:
        print_pass("Rate limiter blocked excessive requests")
    else:
        print_fail("Rate limiter DID NOT block excessive requests")

if __name__ == "__main__":
    try:
        reset_system()
        valid_payload = test_normal_flow()
        test_replay_attack(valid_payload)
        test_injection_attack()
        test_mitm_attack()
        test_dos_attack()
        print("\n--- Verification Complete ---")
    except requests.exceptions.ConnectionError:
        print_fail("Could not connect to server. Is it running?")
