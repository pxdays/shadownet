"""ShadowNet - Secret & API Key Scanner"""
import urllib.request
import re
import ssl
from datetime import datetime

DESCRIPTION = "Scan HTML/JS for exposed API keys, tokens, and secrets"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 120

SECRET_PATTERNS = {
    "AWS Access Key": (r'AKIA[0-9A-Z]{16}', "Amazon AWS Access Key ID"),
    "AWS Secret Key": (r'(?i)aws[_-]?secret[_-]?key[^=]*=[^=]*["\']([^"\']+)', "Amazon AWS Secret Access Key"),
    "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    "Google OAuth": (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "Google OAuth Client ID"),
    "Slack Token": (r'(xox[baprs]-[0-9a-zA-Z-]+)', "Slack API Token"),
    "GitHub Token": (r'(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    "GitLab Token": (r'glpat-[0-9a-zA-Z\-_]{20,}', "GitLab Personal Access Token"),
    "JWT Token": (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JSON Web Token"),
    "Private Key": (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key (possibly exposed)"),
    "Stripe Key": (r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', "Stripe API Key"),
    "Twilio Key": (r'SK[0-9a-f]{32}', "Twilio API Key"),
    "Facebook Secret": (r'(?i)facebook[_-]?secret[^=]*=[^=]*["\']([^"\']+)', "Facebook App Secret"),
    "Discord Token": (r'[MN][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6,7}\.[0-9A-Za-z_-]{27}', "Discord Bot Token"),
    "Heroku API": (r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', "Heroku API Key"),
    "Generic Password": (r'(?i)password\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded Password"),
    "API Key Generic": (r'(?i)api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', "Generic API Key"),
    "Secret Generic": (r'(?i)secret\s*[=:]\s*["\'][^"\']{8,}["\']', "Generic Secret"),
    "MongoDB URI": (r'mongodb(?:\+srv)?://[^\s\'"]+', "MongoDB Connection String"),
    "MySQL URI": (r'mysql://[^\s\'"]+', "MySQL Connection String"),
    "PostgreSQL URI": (r'postgres(?:ql)?://[^\s\'"]+', "PostgreSQL Connection String"),
    "Redis URI": (r'redis://[^\s\'"]+', "Redis Connection String"),
    "Telegram Bot Token": (r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}', "Telegram Bot Token"),
}

def run(target, engine):
    base_url = target['url'].rstrip('/')
    engine.print_status(f"Scanning for exposed secrets and API keys on {base_url}...", "error")
    
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Pages to scrape
    pages_to_check = [base_url]
    
    # Try to find JS files and other pages
    try:
        req = urllib.request.Request(base_url, headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = resp.read(200000).decode('utf-8', errors='ignore')
        
        # Find script tags
        js_files = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.IGNORECASE)
        for js in js_files[:30]:
            if js.startswith('http'):
                pages_to_check.append(js)
            elif js.startswith('/'):
                pages_to_check.append(base_url.rstrip('/') + js)
            else:
                pages_to_check.append(base_url.rstrip('/') + '/' + js)
        
        # Find source maps
        source_maps = re.findall(r'//# sourceMappingURL=([^\s]+)', body, re.IGNORECASE)
        for sm in source_maps:
            if sm.startswith('http'):
                pages_to_check.append(sm)
            elif sm.startswith('/'):
                pages_to_check.append(base_url.rstrip('/') + sm)
    except Exception:
        pass
    
    engine.print_status(f"Checking {len(pages_to_check)} pages for secrets...", "info")
    
    checked = 0
    for page in pages_to_check[:20]:
        try:
            checked += 1
            engine.print_status(f"  Scanning {page[:60]}...", "info")
            
            req = urllib.request.Request(page, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            content = resp.read(300000).decode('utf-8', errors='ignore')
            
            for secret_name, (pattern, description) in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches[:3]:  # Max 3 per pattern per page
                    # Mask the secret for safety
                    masked = match[:8] + '*' * (len(match) - 12) + match[-4:] if len(match) > 12 else match[:4] + '****'
                    
                    engine.print_status(f"  ⚠️  {secret_name}: {masked}", "error")
                    findings.append({
                        "severity": "critical",
                        "title": f"Exposed {secret_name}",
                        "description": f"Found potential {description} in {page}",
                        "detail": f"Source: {page}\nType: {secret_name}\nMatch: {masked}\n\nWARNING: This secret should be revoked immediately.",
                        "remediation": f"Revoke the exposed {secret_name} immediately. Remove it from the codebase and use environment variables or a secrets manager.",
                        "raw_data": {"source": page, "type": secret_name, "pattern": pattern}
                    })
        except Exception:
            pass
    
    if not findings:
        engine.print_status("No exposed secrets found (basic scan)", "ok")
    
    return findings

