"""ShadowNet - WHOIS Lookup Module"""
import socket
import subprocess
import re
from datetime import datetime

DESCRIPTION = "Perform WHOIS lookups for domain registration and IP ownership info"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 60

def _parse_date(date_str):
    """Parse date string without external dependencies"""
    date_str = date_str.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%Y/%m/%d",
        "%d %b %Y",
        "%d %B %Y",
        "%B %d %Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

def _days_until(date_str):
    """Calculate days until a date"""
    parsed = _parse_date(date_str)
    if parsed:
        # Handle timezone-aware vs naive
        now = datetime.now()
        if parsed.tzinfo:
            # Make now timezone-aware (using system timezone info would need tzlocal)
            # For simplicity, strip tz and compare naive
            parsed = parsed.replace(tzinfo=None)
        diff = (parsed - now).days
        return diff
    return None

def run(target, engine):
    hostname = target['hostname']
    engine.print_status(f"Performing WHOIS lookup for {hostname}...", "info")
    
    findings = []
    
    # Try using whois command if available
    try:
        result = subprocess.run(['whois', hostname], capture_output=True, text=True, timeout=15)
        whois_text = result.stdout
    except Exception:
        # Fallback: use a whois service via socket
        whois_text = _whois_socket(hostname)
    
    if not whois_text or len(whois_text) < 50:
        engine.print_status("WHOIS data unavailable (rate limited or blocked)", "warn")
        return []
    
    interesting = []
    
    for pattern, label in [
        (r'Creation Date:\s*(.+)', 'Creation Date'),
        (r'created:\s*(.+)', 'Creation Date'),
        (r'Registry Expiry Date:\s*(.+)', 'Expiry Date'),
        (r'expire:\s*(.+)', 'Expiry Date'),
        (r'Registrar:\s*(.+)', 'Registrar'),
        (r'Registrant (?:Name|Organization):\s*(.+)', 'Registrant'),
        (r'Admin (?:Name|Organization):\s*(.+)', 'Admin'),
        (r'Tech (?:Name|Organization):\s*(.+)', 'Tech'),
        (r'Name Server:\s*(.+)', 'Name Server'),
        (r'DNSSEC:\s*(.+)', 'DNSSEC'),
        (r'Domain Status:\s*(.+)', 'Domain Status'),
    ]:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            value = match.group(1).strip() if len(match.groups()) == 1 else match.group(2).strip()
            interesting.append(f"{label}: {value}")
    
    if interesting:
        engine.print_status(f"WHOIS data retrieved", "ok")
        for line in interesting[:6]:
            engine.print_status(f"  {line}", "info")
        
        # Check if domain is expiring soon
        for line in interesting:
            if 'Expiry Date' in line:
                date_val = line.split(': ', 1)[1] if ': ' in line else ''
                days_left = _days_until(date_val)
                if days_left is not None and days_left < 30:
                    findings.append({
                        "severity": "high",
                        "title": f"Domain Expiring Soon ({days_left} days)",
                        "description": f"The domain {hostname} expires in {days_left} days",
                        "detail": f"Expiry: {date_val}\nDays left: {days_left}",
                        "remediation": "Renew the domain immediately to prevent service disruption or domain hijacking.",
                        "raw_data": {"expiry": date_val, "days_left": days_left}
                    })
                break
        
        findings.append({
            "severity": "info",
            "title": f"WHOIS Data for {hostname}",
            "description": "Domain registration information retrieved",
            "detail": '\n'.join(interesting),
            "remediation": "Consider WHOIS privacy protection to hide personal registration details.",
            "raw_data": {"whois_lines": interesting}
        })
    else:
        engine.print_status("No recognizable WHOIS fields found", "warn")
    
    return findings

def _whois_socket(domain):
    """Basic WHOIS lookup via raw socket connection"""
    try:
        tld = domain.split('.')[-1]
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'io': 'whois.nic.io',
            'co': 'whois.nic.co',
        }
        server = whois_servers.get(tld, f'whois.nic.{tld}')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.send(f"{domain}\r\n".encode())
        
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        
        sock.close()
        result = data.decode('utf-8', errors='ignore')
        return result
    except Exception:
        return ""

