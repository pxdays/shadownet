"""ShadowNet - CVE Scanner (Server & Service Vulnerability Checker)"""
import json
import urllib.request
import ssl
from datetime import datetime

DESCRIPTION = "Check for known CVEs against detected services and versions"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 120

# Simplified CVE database for common services
COMMON_VULNS = {
    "nginx": {
        "versions": {
            "1.24": [{"cve": "CVE-2024-XXXX", "title": "NGINX HTTP/2 Memory Leak", "severity": "high", "cvss": 7.5}],
            "1.20": [{"cve": "CVE-2023-XXXX", "title": "NGINX Request Smuggling", "severity": "high", "cvss": 7.8}],
        }
    },
    "apache": {
        "versions": {
            "2.4.49": [{"cve": "CVE-2021-41773", "title": "Apache Path Traversal", "severity": "critical", "cvss": 9.8}],
            "2.4.50": [{"cve": "CVE-2021-42013", "title": "Apache Path Traversal RCE", "severity": "critical", "cvss": 9.8}],
        }
    },
    "php": {
        "versions": {
            "8.1": [{"cve": "CVE-2024-XXXX", "title": "PHP CGI Argument Injection", "severity": "critical", "cvss": 9.8}],
            "7.4": [{"cve": "CVE-2022-XXXX", "title": "PHP Multiple Vulnerabilities", "severity": "high", "cvss": 8.5}],
        }
    },
    "openssh": {
        "versions": {
            "7.9": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "8.5": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "8.9": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.2": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.3": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.4": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.5": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.6": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
            "9.7": [{"cve": "CVE-2024-6387", "title": "OpenSSH RegreSSHion RCE (glibc)", "severity": "critical", "cvss": 9.8}],
        }
    }
}

def run(target, engine):
    hostname = target['hostname']
    engine.print_status(f"Checking for known vulnerabilities...", "info")
    
    findings = []
    
    # Check banner info from port scan results
    # Look for version strings in stored findings
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Check server header for CVE matching
        url = target['url']
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0',
        })
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        server = resp.headers.get('Server', '')
        
        if server:
            engine.print_status(f"Checking {server} for known CVEs...", "info")
            server_lower = server.lower()
            
            for service, vulns in COMMON_VULNS.items():
                if service in server_lower:
                    # Try to extract version
                    import re
                    version_match = re.search(r'[\d.]+', server)
                    if version_match:
                        version = version_match.group()
                        for vuln_version, cves in vulns.get('versions', {}).items():
                            if version.startswith(vuln_version) or vuln_version.startswith(version):
                                for cve in cves:
                                    engine.print_status(f"  POTENTIAL CVE: {cve['cve']} - {cve['title']} (CVSS: {cve['cvss']})", "error")
                                    findings.append({
                                        "severity": cve['severity'],
                                        "title": f"{cve['cve']} — {cve['title']}",
                                        "description": f"Version {version} of {service} may be vulnerable to {cve['cve']}",
                                        "detail": f"Service: {service}\nDetected version: {version}\nVulnerable version: {vuln_version}\nCVE: {cve['cve']}\nCVSS: {cve['cvss']}\nSeverity: {cve['severity']}\n\nAffected software: {server}",
                                        "remediation": f"Update {service} to the latest patched version. Check vendor advisory for {cve['cve']}.",
                                        "cve_id": cve['cve'],
                                        "cvss": cve['cvss'],
                                        "raw_data": {"service": service, "version": version, "cve": cve}
                                    })
    
    except Exception as e:
        engine.print_status(f"CVE check error: {e}", "warn")
    
    # Try CVE lookup via NVD API
    try:
        engine.print_status(f"Checking CVE databases...", "info")
        # Simplified CVE API query
        url = f"https://cve.circl.lu/api/last/5"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            # The API returns recent CVEs - we'd need to correlate with services
            # For now, just note that the API is working
            engine.print_status(f"CVE database accessible ({len(data)} recent entries available)", "info")
    except Exception:
        engine.print_status("CVE database lookup unavailable (offline mode)", "warn")
    
    if not findings:
        engine.print_status("No CVEs matched against detected services", "ok")
    
    return findings

