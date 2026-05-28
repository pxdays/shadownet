"""ShadowNet - Subdomain Scanner Module"""
import socket
import concurrent.futures
import ssl
from datetime import datetime

DESCRIPTION = "Enumerate subdomains using DNS brute-force and certificate transparency"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 300

def run(target, engine):
    """Run subdomain enumeration"""
    hostname = target['hostname']
    engine.print_status(f"Brute-forcing subdomains for {hostname}...", "info")
    
    found = []
    checked = 0
    
    from core.utils import load_wordlist
    
    wordlist = load_wordlist("subdomains.txt")
    
    def check_sub(sub):
        nonlocal checked
        full = f"{sub}.{hostname}"
        try:
            ip = socket.gethostbyname(full)
            checked += 1
            
            try:
                host = socket.gethostbyaddr(ip)
                hostname_info = host[0]
            except Exception:
                hostname_info = ""
            
            has_https = False
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=full, timeout=3) as s:
                    s.connect((full, 443))
                    has_https = True
                    s.close()
            except Exception:
                pass
            
            return {
                "subdomain": full,
                "ip": ip,
                "hostname": hostname_info,
                "has_https": has_https,
            }
        except Exception:
            checked += 1
            return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_sub, sub): sub for sub in wordlist}
        done = 0
        total = len(wordlist)
        
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if done % 20 == 0:
                engine.print_status(f"DNS scan: {done}/{total} checked, {len(found)} found", "info")
            
            result = future.result()
            if result:
                found.append(result)
                engine.print_status(f"  → {result['subdomain']} ({result['ip']})", "ok")
    
    # Certificate Transparency via crt.sh
    engine.print_status(f"Checking Certificate Transparency logs...", "info")
    try:
        import urllib.request
        import json
        url = f"https://crt.sh/?q=%25.{hostname}&output=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            ct_data = json.loads(resp.read())
            seen = {f['subdomain'] for f in found}
            for entry in ct_data:
                name = entry.get('name_value', '').strip()
                if name and name not in seen and hostname in name:
                    seen.add(name)
                    found.append({
                        "subdomain": name,
                        "ip": "",
                        "hostname": "",
                        "has_https": False,
                        "source": "crt.sh"
                    })
                    engine.print_status(f"  → {name} (via crt.sh)", "ok")
    except Exception as e:
        engine.print_status(f"crt.sh lookup: {e}", "warn")
    
    if not found:
        engine.print_status("No subdomains found (try a larger wordlist)", "warn")
        return []
    
    engine.print_status(f"Found {len(found)} subdomains", "ok")
    return [{
        "severity": "info",
        "title": f"Subdomain: {f['subdomain']}",
        "description": f"Discovered subdomain resolving to {f.get('ip', 'unknown')}",
        "detail": f"IP: {f.get('ip', 'N/A')}\nHostname: {f.get('hostname', 'N/A')}\nHTTPS: {f.get('has_https', False)}\nSource: {'DNS brute-force' if f.get('ip') else 'crt.sh'}",
        "remediation": "Review if this subdomain should be publicly accessible.",
        "raw_data": f
    } for f in found]

