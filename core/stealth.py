"""ShadowNet - Stealth Mode (Evasion & OPSEC)"""
import random
import time
import socket
import ssl

class StealthEngine:
    """Evasion techniques to avoid detection"""
    
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.proxy_list = []
        self.current_proxy = None
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        ]
        self.referrers = [
            "https://www.google.com/search?q=",
            "https://www.bing.com/search?q=",
            "https://duckduckgo.com/?q=",
            "https://t.co/",
            "https://l.facebook.com/l.php?u=",
        ]
    
    def random_delay(self, min_s=0.5, max_s=3.0):
        """Random delay between requests"""
        if self.enabled:
            delay = random.uniform(min_s, max_s)
            time.sleep(delay)
            return delay
        return 0
    
    def random_user_agent(self):
        """Get a random user agent"""
        return random.choice(self.user_agents)
    
    def random_referrer(self):
        """Get a random referrer"""
        return random.choice(self.referrers)
    
    def rotate_ip(self):
        """Rotate through proxies (if configured)"""
        if not self.enabled or not self.proxy_list:
            return None
        
        proxy = random.choice(self.proxy_list)
        self.current_proxy = proxy
        return proxy
    
    def get_headers(self):
        """Get stealth HTTP headers"""
        headers = {
            'User-Agent': self.random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en-US,en;q=0.7,fr;q=0.3']),
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if self.enabled and random.random() < 0.3:
            headers['Referer'] = self.random_referrer()
        
        return headers
    
    def get_socket_ctx(self):
        """Get SSL context for stealth scanning"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        if hasattr(ssl, 'OP_NO_COMPRESSION'):
            ctx.options |= ssl.OP_NO_COMPRESSION
        
        # Randomize cipher preference
        ciphers = [
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
        ]
        try:
            ctx.set_ciphers(':'.join(ciphers))
        except Exception:
            pass
        
        return ctx

