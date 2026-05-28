"""ShadowNet - Technology Stack Detection Module"""
import urllib.request
import re
import json
import ssl
from datetime import datetime

DESCRIPTION = "Detect web technologies, frameworks, and server software"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 120

SIGNATURES = {
    'server_headers': {
        'cloudflare': ['cloudflare', '__cfduid'],
        'nginx': ['nginx'],
        'apache': ['apache'],
        'iis': ['iis', 'microsoft-iis'],
        'node.js': ['node.js', 'express'],
        'python': ['python', 'uvicorn', 'gunicorn', 'django', 'flask'],
        'php': ['php', 'x-powered-by: php'],
        'ruby': ['ruby', 'rails', 'passenger', 'rack'],
        'java': ['java', 'tomcat', 'jetty', 'jboss', 'spring'],
        'go': ['go', 'gin', 'fiber'],
        'cloudfront': ['cloudfront', 'x-amz-cf'],
        's3': ['s3', 'x-amz-request-id'],
        'github pages': ['github.com'],
        'wordpress': ['wp-', 'wordpress'],
        'shopify': ['shopify', 'x-shopid'],
        'wix': ['wix'],
    },
    'cookies': {
        'php': ['phpsessid'],
        'laravel': ['laravel_session'],
        'django': ['csrftoken', 'sessionid'],
        'rails': ['_session_id'],
        'node.js': ['connect.sid'],
        'express': ['express:sess'],
        'wordpress': ['wordpress_', 'wp-settings'],
        'shopify': ['_shopify'],
        'cloudflare': ['__cfduid'],
    },
    'paths': {
        'wordpress': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-json/'],
        'drupal': ['/sites/default/', '/core/'],
        'joomla': ['/administrator/', '/components/'],
        'laravel': ['/vendor/', '/artisan'],
        'next.js': ['/_next/'],
        'react': ['/static/js/main.', 'react'],
        'angular': ['angular', 'ng-version'],
        'vue': ['vue.js', 'vue.min.js'],
        'jquery': ['jquery'],
        'bootstrap': ['bootstrap'],
        'tailwind': ['tailwind'],
    }
}

def run(target, engine):
    hostname = target['hostname']
    url = target['url']
    engine.print_status(f"Detecting technology stack for {url}...", "info")
    
    findings = []
    detected = {}
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        resp = urllib.request.urlopen(req, timeout=8, context=ctx)
        headers = dict(resp.headers)
        body = resp.read(50000).decode('utf-8', errors='ignore')
        status = resp.status
        
        engine.print_status(f"HTTP {status} — {len(body)} bytes", "info")
        
        # Check server header
        server = headers.get('Server', headers.get('server', ''))
        engine.print_status(f"Server: {server or 'Unknown'}", "info")
        
        # Check headers for tech
        for tech, sigs in SIGNATURES['server_headers'].items():
            for sig in sigs:
                if sig.lower() in server.lower():
                    detected[tech] = f"Header: {server}"
                    break
        
        # Check all response headers
        all_headers = {k.lower(): v for k, v in headers.items()}
        for header, value in all_headers.items():
            for tech, sigs in SIGNATURES['server_headers'].items():
                for sig in sigs:
                    if sig.lower() in value.lower() or sig.lower() in f"{header}: {value}".lower():
                        if tech not in detected:
                            detected[tech] = f"Header {header}: {value}"
        
        # Check cookies
        set_cookie = all_headers.get('set-cookie', '')
        for tech, sigs in SIGNATURES['cookies'].items():
            for sig in sigs:
                if sig.lower() in set_cookie.lower():
                    detected[tech] = f"Cookie: {sig}"
                    break
        
        # Check body content
        body_lower = body.lower()
        for tech, sigs in SIGNATURES['paths'].items():
            for sig in sigs:
                if sig.lower() in body_lower:
                    if tech not in detected:
                        detected[tech] = f"Body contains: {sig}"
                    break
        
        # Check X-Powered-By
        xpb = all_headers.get('x-powered-by', '')
        if xpb:
            detected[xpb.lower()] = f"X-Powered-By: {xpb}"
        
        # Security headers check
        security_headers = {
            'strict-transport-security': 'HSTS',
            'content-security-policy': 'CSP',
            'x-frame-options': 'Clickjacking Protection',
            'x-content-type-options': 'MIME Sniffing Protection',
            'x-xss-protection': 'XSS Protection',
            'referrer-policy': 'Referrer Policy',
            'permissions-policy': 'Permissions Policy',
            'access-control-allow-origin': 'CORS',
        }
        
        missing_sec = []
        present_sec = []
        for hdr, label in security_headers.items():
            if hdr in all_headers:
                present_sec.append(f"  ✅ {label} ({hdr}: {all_headers[hdr][:50]})")
            else:
                missing_sec.append(f"  ❌ {label} ({hdr})")
        
        if missing_sec:
            engine.print_status(f"Missing security headers ({len(missing_sec)}):", "warn")
            for h in missing_sec[:4]:
                engine.print_status(h, "warn")
        
        # Print detected tech
        if detected:
            engine.print_status(f"Detected technologies:", "ok")
            for tech, source in sorted(detected.items()):
                engine.print_status(f"  {tech.upper():15s} {source}", "ok")
        
        # Findings
        if detected:
            findings.append({
                "severity": "info",
                "title": f"Technology Stack: {', '.join(detected.keys())}",
                "description": f"Detected {len(detected)} technologies on {url}",
                "detail": f"Status: {status}\nServer: {server}\n\nDetected:\n" + '\n'.join(f"  {k}: {v}" for k, v in detected.items()),
                "remediation": "Keep all technologies updated. Remove unnecessary headers that reveal version info.",
                "raw_data": {"technologies": detected, "server": server, "status": status}
            })
        
        if present_sec:
            findings.append({
                "severity": "info",
                "title": f"Security Headers: {len(present_sec)} present",
                "description": f"The following security headers are configured",
                "detail": '\n'.join(present_sec),
                "remediation": "Maintain current security header configuration.",
                "raw_data": {"present_headers": present_sec}
            })
        
        if missing_sec:
            findings.append({
                "severity": "medium",
                "title": f"Missing Security Headers ({len(missing_sec)})",
                "description": f"Important security headers are not configured",
                "detail": '\n'.join(missing_sec),
                "remediation": "Add recommended security headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.",
                "raw_data": {"missing_headers": [h.split(' (')[0].strip('  ❌ ') for h in missing_sec]}
            })
        
    except urllib.error.HTTPError as e:
        engine.print_status(f"HTTP {e.code}", "warn")
        findings.append({
            "severity": "info",
            "title": f"HTTP Status: {e.code}",
            "description": f"Server returned {e.code} for {url}",
            "detail": f"URL: {url}\nStatus: {e.code}",
            "remediation": "No action needed.",
            "raw_data": {"status": e.code}
        })
    except Exception as e:
        engine.print_status(f"Tech detection failed: {e}", "error")
    
    return findings

