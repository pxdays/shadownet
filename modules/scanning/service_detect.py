"""ShadowNet - Service Fingerprinting via Banner Grabbing"""
import socket
import concurrent.futures

DESCRIPTION = "Advanced service fingerprinting and version detection"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 120

PROBES = {
    21: b"HELP\r\n",
    22: None,  # Just grab banner
    25: b"EHLO scan\r\n",
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"CAPA\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: None,  # SSL/TLS - use openssl
    445: None,  # SMB - native protocol
    3306: None,  # MySQL - native protocol
    5432: None,  # PostgreSQL - native protocol
    6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: None,  # SSL/TLS
    27017: None,  # MongoDB
}

def run(target, engine):
    hostname = target['hostname']
    engine.print_status(f"Fingerprinting services on {hostname}...", "info")
    
    findings = []
    
    def probe_service(port, probe):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((hostname, port))
            
            banner = ""
            if probe:
                sock.send(probe)
            
            try:
                data = sock.recv(2048)
                banner = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            
            sock.close()
            
            if banner:
                # Identify service from banner
                service = SERVICES.get(port, 'Unknown')
                version = extract_version(banner, service)
                
                engine.print_status(f"  Port {port}: {service} → {banner[:80]}", "ok")
                return {
                    "port": port,
                    "service": service,
                    "banner": banner[:500],
                    "version": version,
                }
        except Exception:
            pass
        return None
    
    from core.utils import load_wordlist
    ports = load_wordlist("common_ports.txt")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {}
        for port in ports:
            port = int(port)
            probe = PROBES.get(port, None)
            futures[executor.submit(probe_service, port, probe)] = port
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                findings.append({
                    "severity": "info",
                    "title": f"Service: {result['service']} on port {result['port']}",
                    "description": f"Identified {result['service']}{' version ' + result['version'] if result.get('version') else ''} on port {result['port']}",
                    "detail": f"Port: {result['port']}\nService: {result['service']}\nVersion: {result.get('version', 'Unknown')}\nBanner: {result['banner']}",
                    "remediation": "Disable unnecessary services. Keep all services updated to latest stable versions.",
                    "raw_data": result
                })
    
    if not findings:
        engine.print_status("No services fingerprinted", "info")
    
    return findings

SERVICES = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB'
}

def extract_version(banner, service):
    """Extract version string from banner"""
    import re
    patterns = {
        'SSH': r'SSH[-_](\d+\.\d+(?:\.\d+)?)',
        'Apache': r'Apache/(\d+\.\d+(?:\.\d+)?)',
        'nginx': r'nginx/(\d+\.\d+(?:\.\d+)?)',
        'OpenSSH': r'OpenSSH[_-](\d+\.\d+(?:p\d+)?)',
        'vsftpd': r'vsftpd(\d+\.\d+(?:\.\d+)?)',
        'proftpd': r'ProFTPD (\d+\.\d+(?:\.\d+)?)',
        'MySQL': r'(\d+\.\d+(?:\.\d+)?)',
    }
    for srv, pat in patterns.items():
        if srv.lower() in service.lower():
            m = re.search(pat, banner)
            if m:
                return m.group(1)
    return ""

