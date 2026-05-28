"""ShadowNet - Directory & File Brute-Forcer"""
import urllib.request
import concurrent.futures
import ssl
from datetime import datetime

DESCRIPTION = "Brute-force directories and files on web servers"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 300

COMMON_DIRS = [
    "admin", "login", "wp-admin", "administrator", "backup", "backups",
    "config", "configuration", "api", "v1", "v2", "graphql", "rest",
    "uploads", "files", "images", "assets", "css", "js", "static",
    "robots.txt", ".env", ".git/config", "sitemap.xml", "crossdomain.xml",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
    "wp-content", "wp-includes", "vendor", "node_modules", ".htaccess",
    "server-status", "cgi-bin", "logs", "error_log", "debug",
    "dashboard", "manager", "console", "panel", "cpanel", "plesk",
    "phpmyadmin", "pma", "mysql", "dbadmin", "adminer",
    "swagger", "api-docs", "docs", "documentation",
    "health", "healthcheck", "status", "metrics", "prometheus",
    "proxy", "wpad.dat", "clientaccesspolicy.xml",
    ".well-known/security.txt", ".well-known/acme-challenge",
    "s3", "storage", "bucket", "data", "download", "temp", "tmp",
]

EXTENSIONS = ['', '.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.json']

def run(target, engine):
    base_url = target['url'].rstrip('/')
    if not base_url.startswith('http'):
        base_url = f"http://{base_url}"
    
    engine.print_status(f"Scanning directories on {base_url}...", "info")
    
    findings = []
    found = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    targets = []
    for d in COMMON_DIRS:
        targets.append(d)
        for ext in EXTENSIONS:
            if ext:
                targets.append(d + ext)
    
    def check_path(path):
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            req = urllib.request.Request(url, method='HEAD', headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            })
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            size = resp.headers.get('Content-Length', '?')
            return {'url': url, 'status': resp.status, 'size': size}
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 307, 308):
                return {'url': url, 'status': e.code, 'size': 0, 'redirect': e.headers.get('Location', '')}
            return None
        except Exception:
            return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_path, p): p for p in targets}
        done = 0
        total = len(targets)
        
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 30 == 0:
                engine.print_status(f"Scanning paths: {done}/{total}", "info")
            
            result = future.result()
            if result:
                found.append(result)
                if result['status'] in (200, 301, 302, 401, 403):
                    redirect = f" → {result.get('redirect', '')}" if result.get('redirect') else ""
                    engine.print_status(f"  [{result['status']}] {result['url'][len(base_url):]}{redirect}{' ' + result.get('size', '') + 'B' if result.get('size') and result['size'] != '?' else ''}", "ok")
    
    if not found:
        engine.print_status("No accessible paths found", "warn")
        return []
    
    engine.print_status(f"Found {len(found)} accessible paths", "ok")
    
    # Categorize findings
    sensitive_paths = ['.env', '.git', '.htaccess', 'admin', 'config', 'phpmyadmin', 'backup']
    
    for f in found:
        path = f['url'][len(base_url):]
        sev = "info"
        
        # Check for sensitive paths
        if any(sp in path.lower() for sp in sensitive_paths):
            sev = "high" if '.env' in path.lower() or '.git' in path.lower() else "medium"
        
        findings.append({
            "severity": sev,
            "title": f"[{f['status']}] {path or '/'}",
            "description": f"Accessible path found at {f['url']}",
            "detail": f"URL: {f['url']}\nStatus: {f['status']}\nSize: {f.get('size', 'N/A')}",
            "remediation": f"Restrict access to this path if not intended to be public. {'Remove sensitive file from web root.' if sev == 'high' else ''}",
            "raw_data": f
        })
    
    return findings

