"""ShadowNet - Deep JS Crawler & Secret Hunter"""
import urllib.request
import urllib.error
import re
import ssl
import json
from urllib.parse import urljoin, urlparse

DESCRIPTION = "Deep crawl JavaScript files for secrets, API keys, tokens, and endpoints (PREMIUM)"
AUTHOR = "pxdays"
VERSION = "2.0"
REQUIRES = []
TIMEOUT = 300

SECRET_PATTERNS = {
    "AWS Access Key": (r'AKIA[0-9A-Z]{16}', "Amazon AWS Access Key"),
    "AWS Secret Key": (r'(?i)aws[_-]?secret[_-]?key[^=]*=[^=]*["\']([^"\']+)', "AWS Secret Key"),
    "Google API Key": (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    "Google OAuth": (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "Google OAuth ID"),
    "Slack Token": (r'(xox[baprs]-[0-9a-zA-Z-]+)', "Slack Token"),
    "GitHub Token": (r'(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}', "GitHub PAT"),
    "GitLab Token": (r'glpat-[0-9a-zA-Z\-_]{20,}', "GitLab PAT"),
    "JWT Token": (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token"),
    "Stripe Live": (r'(?:sk|pk)_live_[0-9a-zA-Z]{24,}', "Stripe Live Key"),
    "Stripe Test": (r'(?:sk|pk)_test_[0-9a-zA-Z]{24,}', "Stripe Test Key"),
    "Twilio Key": (r'SK[0-9a-f]{32}', "Twilio Key"),
    "Discord Token": (r'[MN][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6,7}\.[0-9A-Za-z_-]{27}', "Discord Bot Token"),
    "Heroku API": (r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', "Heroku Key"),
    "Firebase URL": (r'https://[a-zA-Z0-9_-]+\.firebaseio\.com', "Firebase DB URL"),
    "MongoDB URI": (r'mongodb(?:\+srv)?://[^\s\'"]+', "MongoDB URI"),
    "PostgreSQL URI": (r'postgres(?:ql)?://[^\s\'"]+', "PostgreSQL URI"),
    "MySQL URI": (r'mysql://[^\s\'"]+', "MySQL URI"),
    "Redis URI": (r'redis://[^\s\'"]+', "Redis URI"),
    "Telegram Bot": (r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}', "Telegram Bot Token"),
    "Generic Password": (r'(?i)password\s*[=:]\s*["\'][^"\']{6,}["\']', "Hardcoded Password"),
    "API Key Generic": (r'(?i)api[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']', "Generic API Key"),
    "Secret Generic": (r'(?i)secret\s*[=:]\s*["\'][^"\']{8,}["\']', "Generic Secret"),
    ".env Exposure": (r'(?i)(DB_|DATABASE_|SECRET_|TOKEN_|PASSW|API_)[A-Z_]+[=:].+', "Environment Variable"),
    "Private Key": (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
    "SendGrid Key": (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
    "Mailgun Key": (r'key-[0-9a-zA-Z]{32}', "Mailgun API Key"),
    "Google Service Account": (r'type":\s*"service_account"', "Google Service Account"),
    "npm token": (r'(?i)npm[a-z]*token[^=]*=[^=]*["\']([^"\']+)', "NPM Token"),
    "SSH Private Key inline": (r'-----BEGIN OPENSSH PRIVATE KEY-----', "SSH Private Key"),
}

INTERESTING_ENDPOINTS = [
    r'https?://[^\s\'"]*api[^\s\'"]*',
    r'https?://[^\s\'"]*admin[^\s\'"]*',
    r'https?://[^\s\'"]*graphql[^\s\'"]*',
    r'https?://[^\s\'"]*\.json[^\s\'"]*',
    r'https?://[^\s\'"]*s3\.amazonaws[^\s\'"]*',
    r'https?://[^\s\'"]*firebase[^\s\'"]*',
    r'/[a-zA-Z0-9_-]{30,}/',  # Likely tokens
]

def run(target, engine):
    base_url = target['url'].rstrip('/')
    engine.print_status(f"🚀 DEEP JS CRAWLER — crawling for secrets, keys, and endpoints...", "warn")
    
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Collect all JS URLs
    js_urls = set()
    visited = set()
    to_visit = [base_url]
    
    # Phase 1: Crawl and collect JS files
    engine.print_status("Phase 1: Crawling pages for JavaScript files...", "info")
    
    while to_visit and len(visited) < 15:  # Crawl up to 15 pages
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        
        try:
            engine.print_status(f"  Crawling: {url[:70]}", "info")
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            resp = urllib.request.urlopen(req, timeout=8, context=ctx)
            body = resp.read().decode('utf-8', errors='ignore')
            
            # Find script tags
            for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.IGNORECASE):
                js_url = match.group(1)
                if js_url.startswith('http'):
                    js_urls.add(js_url)
                elif js_url.startswith('//'):
                    js_urls.add('https:' + js_url)
                elif js_url.startswith('/'):
                    js_urls.add(base_url.rstrip('/') + js_url)
                else:
                    js_urls.add(base_url.rstrip('/') + '/' + js_url)
            
            # Find links to other pages (same domain)
            for match in re.finditer(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
                link = match.group(1)
                if not link.startswith('http') and not link.startswith('//') and not link.startswith('#'):
                    full = urljoin(base_url, link)
                    parsed = urlparse(full)
                    # Only follow same-domain
                    if parsed.netloc == urlparse(base_url).netloc:
                        if full not in visited and full not in to_visit:
                            to_visit.append(full)
            
        except Exception as e:
            engine.print_status(f"  Skipped: {e}", "warn")
    
    engine.print_status(f"Phase 2: Scanning {len(js_urls)} JavaScript files...", "warn")
    
    # Phase 2: Scan JS files for secrets
    secrets_found = {}
    
    for js_url in js_urls:
        try:
            req = urllib.request.Request(js_url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            resp = urllib.request.urlopen(req, timeout=8, context=ctx)
            js_content = resp.read(500000).decode('utf-8', errors='ignore')
            
            for secret_name, (pattern, description) in SECRET_PATTERNS.items():
                matches = re.findall(pattern, js_content)
                for match in matches[:3]:
                    if isinstance(match, tuple):
                        match = match[0]
                    masked = match[:8] + '*' * max(0, min(len(match) - 12, 20)) + match[-4:] if len(match) > 12 else match[:4] + '****'
                    
                    if secret_name not in secrets_found:
                        secrets_found[secret_name] = []
                    
                    if match not in [s['raw'] for s in secrets_found[secret_name]]:
                        secrets_found[secret_name].append({
                            'source': js_url,
                            'masked': masked,
                            'raw': match[:20]  # Store only partial for safety
                        })
                        
                        engine.print_status(f"  🔑 [{secret_name}] {masked}", "error")
            
            # Find API endpoints
            for pattern in INTERESTING_ENDPOINTS:
                endpoints = re.findall(pattern, js_content)
                for ep in endpoints[:5]:
                    if 'secret' not in secrets_found:
                        secrets_found['API Endpoint'] = []
                    if ep not in [s['raw'] for s in secrets_found.get('API Endpoint', [])]:
                        secrets_found.setdefault('API Endpoint', []).append({
                            'source': js_url,
                            'raw': ep[:80]
                        })
                        engine.print_status(f"  🔗 Endpoint: {ep[:80]}", "info")
                        
        except Exception as e:
            engine.print_status(f"  JS scan error: {e}", "warn")
    
    # Generate findings
    for secret_type, instances in secrets_found.items():
        if secret_type == 'API Endpoint':
            sev = "medium"
        elif secret_type in ('Private Key', 'AWS Secret Key', 'Stripe Live', 'GitHub Token'):
            sev = "critical"
        else:
            sev = "high"
        
        sources = set(s['source'] for s in instances)
        engine.print_status(f"  {'⚠️' if sev in ('critical','high') else 'ℹ️'} {secret_type}: {len(instances)} found in {len(sources)} files", 
                          "error" if sev == 'critical' else "warn" if sev == 'high' else "info")
        
        findings.append({
            "severity": sev,
            "title": f"{len(instances)}x {secret_type} Found",
            "description": f"Found {len(instances)} potential {secret_type} in JavaScript files",
            "detail": f"Type: {secret_type}\nInstances: {len(instances)}\nSources: {', '.join(sources)[:500]}\n\nExamples:\n" + '\n'.join(f"  • {s['masked'][:40]} — {s['source'][:60]}" for s in instances[:5]),
            "remediation": f"Revoke exposed {secret_type} immediately. Remove from client-side code. Use environment variables or a secrets manager.",
            "raw_data": {"type": secret_type, "count": len(instances), "sources": list(sources)}
        })
    
    if not findings:
        engine.print_status("No secrets found in JavaScript files", "ok")
    else:
        engine.print_status(f"Deep crawl complete: {len(findings)} secret types identified", "error")
    
    return findings
