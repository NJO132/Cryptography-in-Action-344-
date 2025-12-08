
import requests
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed



TARGET_URL = "http://127.0.0.1:5000/api/attack/dos/test"
RESET_URL = "http://127.0.0.1:5000/api/attack/dos/reset"
STATUS_URL = "http://127.0.0.1:5000/api/attack/dos/status"

# Attack parameters
NUM_REQUESTS = 25  # Total requests to send
DELAY_BETWEEN_REQUESTS = 0.1  # Seconds between requests (100ms)
CONCURRENT_THREADS = 1  # Number of concurrent threads (1 = sequential attack)


def print_banner():
    """Print the attack script banner."""
    print("""

       
       
       
             DOS Attack!!!!

    """)


def print_colored(text, color_code):
    """Print colored text to terminal."""
    print(f"\033[{color_code}m{text}\033[0m")


def print_success(text):
    """Print success message in green."""
    print_colored(f"[✓] {text}", "92")


def print_error(text):
    """Print error message in red."""
    print_colored(f"[✗] {text}", "91")


def print_warning(text):
    """Print warning message in yellow."""
    print_colored(f"[!] {text}", "93")


def print_info(text):
    """Print info message in cyan."""
    print_colored(f"[*] {text}", "96")




def check_server():
    """Check if the server is running and accessible."""
    print_info("Checking server status...")
    try:
        response = requests.get(STATUS_URL, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_success("Server is running!")
            print_info(f"Rate limit configuration: {data['explanation']}")
            return True
        else:
            print_error(f"Unexpected response: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_error("Cannot connect to server. Make sure Flask app is running!")
        print_info("Start the server with: python app.py")
        return False
    except Exception as e:
        print_error(f"Error: {e}")
        return False


def reset_rate_limiter():
    """Reset the rate limiter before attack."""
    print_info("Resetting rate limiter...")
    try:
        response = requests.post(RESET_URL, timeout=5)
        if response.status_code == 200:
            print_success("Rate limiter reset!")
            return True
        else:
            print_warning("Could not reset rate limiter")
            return False
    except Exception as e:
        print_error(f"Error resetting: {e}")
        return False


def send_attack_request(request_num):

    start_time = time.time()
    
    try:
        response = requests.post(TARGET_URL, json={}, timeout=10)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            data = response.json()
            return {
                'request_num': request_num,
                'status': 'allowed',
                'status_code': 200,
                'remaining': data.get('requests_remaining', 'N/A'),
                'elapsed': elapsed
            }
        elif response.status_code == 429:
            data = response.json()
            return {
                'request_num': request_num,
                'status': 'blocked',
                'status_code': 429,
                'error': data.get('error', 'Rate limited'),
                'elapsed': elapsed
            }
        else:
            return {
                'request_num': request_num,
                'status': 'error',
                'status_code': response.status_code,
                'error': f"Unexpected status: {response.status_code}",
                'elapsed': elapsed
            }
            
    except requests.exceptions.Timeout:
        return {
            'request_num': request_num,
            'status': 'timeout',
            'error': 'Request timed out',
            'elapsed': time.time() - start_time
        }
    except requests.exceptions.ConnectionError:
        return {
            'request_num': request_num,
            'status': 'connection_error',
            'error': 'Connection refused',
            'elapsed': time.time() - start_time
        }
    except Exception as e:
        return {
            'request_num': request_num,
            'status': 'error',
            'error': str(e),
            'elapsed': time.time() - start_time
        }


def run_sequential_attack():
    """
    Run a sequential DoS attack (one request at a time).
    """
    print_info("Starting SEQUENTIAL DoS attack...")
    print_info(f"Target: {TARGET_URL}")
    print_info(f"Total requests: {NUM_REQUESTS}")
    print_info(f"Delay between requests: {DELAY_BETWEEN_REQUESTS}s")
    print()
    
    results = {
        'allowed': 0,
        'blocked': 0,
        'errors': 0,
        'total_time': 0
    }
    
    start_time = time.time()
    first_block_at = None
    
    for i in range(1, NUM_REQUESTS + 1):
        result = send_attack_request(i)
        results['total_time'] += result.get('elapsed', 0)
        
        if result['status'] == 'allowed':
            results['allowed'] += 1
            print_success(f"Request #{i}: ALLOWED (remaining: {result['remaining']}, {result['elapsed']*1000:.0f}ms)")
        elif result['status'] == 'blocked':
            results['blocked'] += 1
            if first_block_at is None:
                first_block_at = i
                print()
                print_warning("=" * 60)
                print_warning("  RATE LIMITER ACTIVATED! DoS Defense Working!")
                print_warning("=" * 60)
                print()
            print_error(f"Request #{i}: BLOCKED - {result['error']}")
        else:
            results['errors'] += 1
            print_warning(f"Request #{i}: ERROR - {result.get('error', 'Unknown error')}")
        
        # Delay between requests
        if i < NUM_REQUESTS:
            time.sleep(DELAY_BETWEEN_REQUESTS)
    
    total_elapsed = time.time() - start_time
    
    return results, first_block_at, total_elapsed


def run_burst_attack():
    """
    Run a burst DoS attack (multiple concurrent requests).
    """
    print_info("Starting BURST DoS attack...")
    print_info(f"Target: {TARGET_URL}")
    print_info(f"Total requests: {NUM_REQUESTS}")
    print_info(f"Concurrent threads: {CONCURRENT_THREADS}")
    print()
    
    results = {
        'allowed': 0,
        'blocked': 0,
        'errors': 0,
        'total_time': 0
    }
    
    start_time = time.time()
    first_block_at = None
    lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=CONCURRENT_THREADS) as executor:
        futures = {executor.submit(send_attack_request, i): i 
                   for i in range(1, NUM_REQUESTS + 1)}
        
        for future in as_completed(futures):
            result = future.result()
            
            with lock:
                results['total_time'] += result.get('elapsed', 0)
                
                if result['status'] == 'allowed':
                    results['allowed'] += 1
                    print_success(f"Request #{result['request_num']}: ALLOWED ({result['elapsed']*1000:.0f}ms)")
                elif result['status'] == 'blocked':
                    results['blocked'] += 1
                    if first_block_at is None:
                        first_block_at = result['request_num']
                        print()
                        print_warning("=" * 60)
                        print_warning("  RATE LIMITER ACTIVATED!")
                        print_warning("=" * 60)
                        print()
                    print_error(f"Request #{result['request_num']}: BLOCKED")
                else:
                    results['errors'] += 1
                    print_warning(f"Request #{result['request_num']}: ERROR")
    
    total_elapsed = time.time() - start_time
    
    return results, first_block_at, total_elapsed


def print_results(results, first_block_at, total_elapsed):
    """Print attack results summary."""
    print()
    print("=" * 70)
    print("                        ATTACK RESULTS SUMMARY")
    print("=" * 70)
    print()
    
    total = results['allowed'] + results['blocked'] + results['errors']
    
    print(f"  Total Requests Sent:     {total}")
    print(f"  ├── Allowed:             {results['allowed']} ({results['allowed']/total*100:.1f}%)")
    print(f"  ├── Blocked (429):       {results['blocked']} ({results['blocked']/total*100:.1f}%)")
    print(f"  └── Errors:              {results['errors']} ({results['errors']/total*100:.1f}%)")
    print()
    print(f"  Attack Duration:         {total_elapsed:.2f} seconds")
    print(f"  Avg Response Time:       {results['total_time']/total*1000:.0f} ms")
    
    if first_block_at:
        print()
        print_success(f"  Rate limiter triggered at request #{first_block_at}")
        print_success("  DoS DEFENSE IS WORKING CORRECTLY!")
    else:
        print()
        print_warning("  Rate limiter was never triggered")
        print_warning("  Either limit is higher or attack was too slow")
    
    print()
    print("=" * 70)
    print()


def main():
    """Main function to run the DoS attack simulation."""
    print_banner()
    
    # Check if server is running
    if not check_server():
        sys.exit(1)
    
    print()
    
    # Ask user to confirm
    print_warning("This script will send multiple requests to test rate limiting.")
    print_warning("Make sure you are only testing against YOUR OWN server!")
    print()
    
    choice = input("Select attack mode:\n"
                   "  1. Sequential attack (one request at a time)\n"
                   "  2. Burst attack (concurrent requests)\n"
                   "  3. Reset rate limiter and exit\n"
                   "  Q. Quit\n"
                   "\nYour choice [1/2/3/Q]: ").strip().lower()
    
    if choice == 'q':
        print_info("Exiting...")
        sys.exit(0)
    elif choice == '3':
        reset_rate_limiter()
        print_success("Rate limiter reset. Exiting...")
        sys.exit(0)
    elif choice not in ['1', '2']:
        print_error("Invalid choice!")
        sys.exit(1)
    
    print()
    
    # Reset rate limiter before attack
    if input("Reset rate limiter before attack? [Y/n]: ").strip().lower() != 'n':
        reset_rate_limiter()
        time.sleep(0.5)  # Brief pause
    
    print()
    print_warning("Starting attack in 3 seconds...")
    for i in range(3, 0, -1):
        print(f"  {i}...")
        time.sleep(1)
    print()
    
    # Run the selected attack
    if choice == '1':
        results, first_block_at, total_elapsed = run_sequential_attack()
    else:
        results, first_block_at, total_elapsed = run_burst_attack()
    
    # Print results
    print_results(results, first_block_at, total_elapsed)
    
    # Offer to reset rate limiter
    if input("Reset rate limiter? [y/N]: ").strip().lower() == 'y':
        reset_rate_limiter()
        print_success("Rate limiter reset!")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_warning("Attack interrupted by user.")
        sys.exit(0)

