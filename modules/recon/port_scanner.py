"""ShadowNet - Port Scanner Module"""
import socket
import concurrent.futures
from datetime import datetime

DESCRIPTION = "TCP port scanning with service fingerprinting"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = []
TIMEOUT = 300

# Common service mappings
SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 2181: 'ZooKeeper',
    2375: 'Docker', 2376: 'Docker TLS', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'RabbitMQ', 5900: 'VNC',
    5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9000: 'PHP-FPM', 9092: 'Kafka', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
    11211: 'Memcached', 27017: 'MongoDB', 50070: 'HDFS'
}

HIGH_RISK_PORTS = [21, 23, 111, 135, 139, 445, 3389, 5900, 6379, 27017]

def run(target, engine):
    hostname = target['hostname']
    engine.print_status(f"Scanning ports on {hostname}...", "info")
    
    findings = []
    open_ports = []
    
    try:
        from core.utils import load_wordlist
    except ImportError:
        from core.utils import load_wordlist
    
    ports = load_wordlist("common_ports.txt")
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((hostname, int(port)))
            sock.close()
            
            if result == 0:
                # Try to grab a banner
                service = SERVICES.get(int(port), 'Unknown')
                banner = ""
                try:
                    gsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    gsock.settimeout(2)
                    gsock.connect((hostname, int(port)))
                    gsock.send(b'HELO\r\n')
                    banner_data = gsock.recv(256)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    gsock.close()
                except Exception:
                    pass
                
                return {
                    'port': int(port),
                    'service': service,
                    'banner': banner,
                    'state': 'open'
                }
        except Exception:
            pass
        return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}
        
        done = 0
        total = len(ports)
        for future in concurrent.futures.as_completed(futures):
            done += 1
            result = future.result()
            if result:
                open_ports.append(result)
                engine.print_status(f"  Port {result['port']:5d}/{result['service']:12s} {'· ' + result['banner'][:40] if result['banner'] else ''}", "ok")
    
    open_ports.sort(key=lambda x: x['port'])
    
    if not open_ports:
        engine.print_status("No open ports found (host may be down or filtered)", "warn")
        return []
    
    engine.print_status(f"Found {len(open_ports)} open ports", "ok")
    
    # Categorize findings
    for p in open_ports:
        sev = "high" if p['port'] in HIGH_RISK_PORTS else "info"
        
        findings.append({
            "severity": sev,
            "title": f"Open Port: {p['port']}/{p['service']}",
            "description": f"Port {p['port']} ({p['service']}) is open on {hostname}",
            "detail": f"Port: {p['port']}\nService: {p['service']}\nBanner: {p['banner'] or 'N/A'}\nState: {p['state']}",
            "remediation": f"Close unused ports. If {p['service']} is needed, ensure it's properly configured, firewalled, and authenticated.",
            "raw_data": p
        })
    
    return findings

