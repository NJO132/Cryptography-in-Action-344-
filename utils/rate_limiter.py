

import time
from collections import defaultdict


class RateLimiter:
    """Simple rate limiter to prevent DoS ."""
    
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
        """Check if an IP is currently blocked."""
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
        """Reset all rate limiting state."""
        self.request_log.clear()
        self.blocked_ips.clear()
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'blocked_ips_count': 0
        }
    
    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        return {
            **self.stats,
            'currently_blocked': list(self.blocked_ips.keys()),
            'rate_limit': self.rate_limit,
            'rate_window': self.rate_window,
            'block_duration': self.block_duration
        }
