"""ShadowNet - Utility Functions"""
import os
import sys
import json
import time
import socket
import random
import hashlib
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import concurrent.futures
from threading import Lock

# Colors - cross platform safe
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        """Disable colors (Windows CMD fallback)"""
        for attr in dir(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, '')

def enable_windows_ansi():
    """Enable ANSI on Windows 10+"""
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            Colors.disable()

def banner():
    """Show ShadowNet banner"""
    return f"""{Colors.RED}
    ╔═══════════════════════════════════════╗
    ║    ███████  ██░ ██  █████   ██████   ║
    ║    ██░░░░░  ████░   ██░░░   ██░░░░   ║
    ║    █████    ██░██   ███████ ██████   ║
    ║    ██░░░    ██░░██  ░░░░██  ░░░░░██  ║
    ║    ███████  ██░ ██  █████   ██████   ║
    ║    ░░░░░░░  ░░  ░░  ░░░░░   ░░░░░░   ║
    ╚═══════════════════════════════════════╝{Colors.RESET}
    {Colors.CYAN}Autonomous Red Team Engine v1.0.0{Colors.RESET}
    {Colors.DIM}Built by pxdays • For educational/authorized testing only{Colors.RESET}
    """

def target_parse(target):
    """Parse a target (URL, IP, domain) into components"""
    target = target.strip()
    parsed = {}
    
    # Remove protocol if present
    if '://' in target:
        parsed['protocol'] = target.split('://')[0]
        target = target.split('://')[1]
    else:
        parsed['protocol'] = 'http'
    
    # Remove path
    if '/' in target:
        parsed['path'] = '/' + '/'.join(target.split('/')[1:])
        target = target.split('/')[0]
    else:
        parsed['path'] = '/'
    
    # Remove port
    if ':' in target:
        parsed['hostname'] = target.split(':')[0]
        parsed['port'] = int(target.split(':')[1])
    else:
        parsed['hostname'] = target
        parsed['port'] = 443 if parsed['protocol'] == 'https' else 80
    
    parsed['target'] = target
    parsed['url'] = f"{parsed['protocol']}://{target}{parsed['path']}"
    return parsed

def is_ip(target):
    """Check if target is an IP address"""
    import re
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(pattern, target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def is_domain(target):
    """Check if target looks like a domain"""
    import re
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, target))

def save_result(target, module, data, output_dir=None):
    """Save scan results to JSON"""
    from .config import Config
    if output_dir is None:
        output_dir = Config.OUTPUT_DIR
    
    safe_name = target.replace('://', '_').replace('/', '_').replace(':', '_')
    out_dir = Path(output_dir) / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)
    
    filename = out_dir / f"{module}_{datetime.now().strftime('%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump({
            "target": target,
            "module": module,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }, f, indent=2, default=str)
    
    return filename

def load_wordlist(name):
    """Load a bundled wordlist"""
    from .config import Config
    path = Config.WORDLISTS_DIR / name
    if path.exists():
        with open(path, errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    
    # Fallback - small built-in list
    return FALLBACK_LISTS.get(name, [])

# Built-in minimal wordlists (no external files needed)
FALLBACK_LISTS = {
    "subdomains.txt": [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "blog", "webmail",
        "vpn", "portal", "secure", "intranet", "ssh", "smtp", "pop3", "dns",
        "support", "help", "forum", "status", "cdn", "static", "assets", "img",
        "download", "app", "mobile", "m", "shop", "store", "admin", "backup",
        "jenkins", "gitlab", "confluence", "jira", "grafana", "prometheus",
        "kibana", "elastic", "monitor", "logs", "stage", "staging", "beta",
        "alpha", "demo", "prod", "production", "dashboard", "metrics"
    ],
    "directories.txt": [
        "admin", "login", "wp-admin", "administrator", "backup", "backups",
        "config", "configuration", "api", "v1", "v2", "graphql", "rest",
        "uploads", "files", "images", "assets", "css", "js", "static",
        "robots.txt", ".env", ".git/config", "sitemap.xml", "crossdomain.xml",
        "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
        "wp-content", "wp-includes", "vendor", "node_modules", ".htaccess",
        "server-status", "cgi-bin", "logs", "error_log", "debug",
    ],
    "common_ports.txt": [
        21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 2049, 2082, 2083, 2181, 2375, 2376, 3306,
        3389, 5432, 5601, 5672, 5900, 5901, 5984, 6379, 6443, 7443, 8000,
        8001, 8080, 8081, 8443, 9000, 9001, 9042, 9092, 9100, 9200, 9300,
        10000, 11211, 27017, 50070
    ]
}

