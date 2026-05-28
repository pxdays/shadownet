"""ShadowNet - DNS Enumeration Module"""
import socket
from datetime import datetime

DESCRIPTION = "Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = ["dnspython"]
TIMEOUT = 120

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA']

# Try to import dns, fail gracefully
try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

def run(target, engine):
    hostname = target['hostname']
    
    if not DNS_AVAILABLE:
        engine.print_status("DNS module requires dnspython: pip install dnspython", "warn")
        return []
    
    engine.print_status(f"Enumerating DNS records for {hostname}...", "info")
    
    findings = []
    
    for rtype in RECORD_TYPES:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(hostname, rtype)
            
            records = []
            for rdata in answers:
                records.append(str(rdata))
            
            if records:
                engine.print_status(f"  {rtype}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}", "ok")
                
                if rtype == 'TXT':
                    for txt in records:
                        if any(k in txt.lower() for k in ['spf', 'v=spf', 'dkim', 'dmarc', 'google-site-verification']):
                            findings.append({
                                "severity": "info",
                                "title": f"TXT Record: {txt[:60]}",
                                "description": f"DNS TXT record found containing auth/verification data",
                                "detail": f"Full record: {txt}",
                                "remediation": "Verify these records are still needed.",
                                "raw_data": {"type": rtype, "records": records}
                            })
                
                if rtype == 'NS':
                    findings.append({
                        "severity": "info",
                        "title": f"Name Servers: {', '.join(records)}",
                        "description": f"DNS name servers found",
                        "detail": f"Records: {', '.join(records)}",
                        "remediation": "Ensure name servers are from a reputable provider.",
                        "raw_data": {"type": rtype, "records": records}
                    })
                
                if rtype == 'MX':
                    findings.append({
                        "severity": "info",
                        "title": f"Mail Servers: {', '.join(records)}",
                        "description": f"DNS MX records found",
                        "detail": f"Records: {', '.join(records)}",
                        "remediation": "Verify mail server configuration.",
                        "raw_data": {"type": rtype, "records": records}
                    })
        
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.exception.Timeout:
            engine.print_status(f"  {rtype}: timeout", "warn")
        except Exception as e:
            engine.print_status(f"  {rtype}: {e}", "warn")
    
    # Zone transfer attempt
    engine.print_status("Attempting DNS zone transfer...", "info")
    try:
        ns_answer = dns.resolver.resolve(hostname, 'NS')
        for ns in ns_answer:
            ns_str = str(ns).rstrip('.')
            try:
                ns_ip = socket.gethostbyname(ns_str)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, hostname, timeout=5, lifetime=10))
                if zone:
                    engine.print_status(f"ZONE TRANSFER SUCCESSFUL from {ns_str}!", "error")
                    findings.append({
                        "severity": "critical",
                        "title": f"DNS Zone Transfer Enabled on {ns_str}",
                        "description": f"DNS zone transfer is enabled, allowing anyone to download the full DNS zone data.",
                        "detail": f"Nameserver: {ns_str}\nIP: {ns_ip}\nRecords: {len(zone.nodes)}",
                        "remediation": "Disable DNS zone transfer for unauthorized hosts."
                    })
            except Exception:
                pass
    except Exception:
        pass
    
    return findings

