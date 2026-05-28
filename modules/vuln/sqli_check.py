"""ShadowNet - SQL Injection Detection Module"""
import urllib.request
import urllib.parse
import ssl
import re

DESCRIPTION = "Detect SQL injection vulnerabilities in web parameters"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 120

SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'; DROP TABLE users--",
    "' WAITFOR DELAY '0:0:5'--",
    "1) OR 1=1--",
    "' OR SLEEP(5)--",
    "' OR pg_sleep(5)--",
]

SQL_ERRORS = [
    "sql syntax", "mysql", "sqlite", "ora-", "oracle", "microsoft ole db",
    "unclosed quotation mark", "mysql_fetch", "sqlsrv", "postgresql",
    "pg_", "you have an error in your sql", "warning: mysql",
    "supplied argument is not a valid mysql", "division by zero in sql",
    "sqlite3", "sqlstate", "driver error", "odbc", "db2",
]

def run(target, engine):
    base_url = target['url'].rstrip('/')
    engine.print_status(f"Testing for SQL injection on {base_url}...", "info")
    
    findings = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # First, crawl the page for forms and links with parameters
    forms_found = []
    
    try:
        req = urllib.request.Request(base_url, headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        body = resp.read().decode('utf-8', errors='ignore')
        
        # Find form actions
        form_matches = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.IGNORECASE)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', body, re.IGNORECASE)
        
        if form_matches or inputs:
            engine.print_status(f"Found {len(form_matches)} forms, {len(inputs)} input fields", "info")
        
        # Find links with parameters (potential injection points)
        param_links = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', body, re.IGNORECASE)
        
        test_urls = []
        if param_links:
            for link in param_links:
                if not link.startswith('http'):
                    link = base_url.rstrip('/') + '/' + link.lstrip('/')
                test_urls.append(link)
        
        # Also try common parameter names on the base URL
        common_params = ['id', 'page', 'user', 'cat', 'category', 'product', 'post', 'article', 'item', 'file', 'pid', 'uid', 'q', 's', 'search']
        test_urls.extend([f"{base_url}?{p}=1" for p in common_params])
        
        # Only test a limited set to avoid being too aggressive
        for test_url in test_urls[:20]:
            for payload in SQL_PAYLOADS[:5]:  # Test first 5 payloads
                try:
                    parsed = urllib.parse.urlparse(test_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    
                    injection_tests = []
                    for param in params:
                        modified = dict(params)
                        modified[param] = [payload]
                        new_query = urllib.parse.urlencode(modified, doseq=True)
                        injected_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                        injection_tests.append((injected_url, param))
                    
                    for injected_url, param in injection_tests:
                        try:
                            inj_req = urllib.request.Request(injected_url, headers={'User-Agent': 'Mozilla/5.0'})
                            inj_resp = urllib.request.urlopen(inj_req, timeout=5, context=ctx)
                            inj_body = inj_resp.read().decode('utf-8', errors='ignore').lower()
                            
                            # Check for SQL errors
                            for error in SQL_ERRORS:
                                if error.lower() in inj_body:
                                    engine.print_status(f"SQL ERROR DETECTED: parameter '{param}' on {test_url.split('?')[0][:50]}", "error")
                                    findings.append({
                                        "severity": "critical",
                                        "title": f"SQL Injection in parameter '{param}'",
                                        "description": f"SQL error pattern '{error}' detected when injecting into {param}",
                                        "detail": f"URL: {test_url.split('?')[0]}\nParameter: {param}\nPayload: {payload}\nError: {error}",
                                        "remediation": "Use parameterized queries / prepared statements. Sanitize all user inputs.",
                                        "raw_data": {"url": injected_url, "param": param, "payload": payload, "error": error}
                                    })
                                    break
                            
                            # Check for boolean-based blind (comparing 1=1 vs 1=2 responses)
                            if "' AND 1=1--" in payload or "' AND 1=2--" in payload:
                                # Store for comparison
                                pass
                        except:
                            pass
                except Exception:
                    pass
    except Exception as e:
        engine.print_status(f"SQLi scan error: {e}", "warn")
    
    if not findings:
        engine.print_status("No SQL injection detected (basic scan)", "ok")
    
    return findings

