"""ShadowNet - Subdomain Takeover Detection"""
import socket
import ssl
import dns.resolver
import urllib.request
import urllib.error

DESCRIPTION = "Check discovered subdomains for dangling DNS (takeover vulnerabilities)"
AUTHOR = "pxdays"
VERSION = "1.0"
REQUIRES = ["dnspython"]
TIMEOUT = 180

# Known fingerprints for unclaimed services
CLOUDS = {
    "github": {
        "cname_patterns": ["github.io", "github.com"],
        "fingerprints": ["There isn't a GitHub Pages site here", "404 - File not found",
                         "Repository not found", "Page not found"]
    },
    "aws": {
        "cname_patterns": ["cloudfront.net", "elasticbeanstalk.com", "s3-website", "s3.amazonaws.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist",
                        "404 Not Found", "CodePipeline"]
    },
    "heroku": {
        "cname_patterns": ["herokuapp.com", "herokudns.com"],
        "fingerprints": ["There's nothing here, yet", "Heroku | No such app",
                        "no-such-app", "Application error"]
    },
    "netlify": {
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID:", "Netlify", "Page Not Found"]
    },
    "shopify": {
        "cname_patterns": ["myshopify.com", "shopify.com"],
        "fingerprints": ["Sorry, this shop is currently unavailable", "Only one more step"]
    },
    "azure": {
        "cname_patterns": ["azurewebsites.net", "trafficmanager.net", "cloudapp.net"],
        "fingerprints": ["There is no site deployed", "404 - Site not found",
                        "The resource you are looking for has been removed"]
    },
    "firebase": {
        "cname_patterns": ["firebaseapp.com", "web.app"],
        "fingerprints": ["Firebase Hosting Client", "Site Not Found", "404"]
    },
    "gitlab": {
        "cname_patterns": ["gitlab.io"],
        "fingerprints": ["The page you're looking for could not be found", "404"]
    },
    "pantheon": {
        "cname_patterns": ["pantheonsite.io"],
        "fingerprints": ["The gods are angry", "pantheon"]
    },
    "wordpress": {
        "cname_patterns": ["wordpress.com"],
        "fingerprints": ["Do you want to register", "Not Found"]
    },
    "surge": {
        "cname_patterns": ["surge.sh"],
        "fingerprints": ["project not found", "404 - not found"]
    },
    "fly.io": {
        "cname_patterns": ["fly.dev", "fly.io"],
        "fingerprints": ["404 Not Found", "page not found"]
    }
}

def run(target, engine):
    hostname = target['hostname']
    engine.print_status(f"Checking {hostname} for subdomain takeover...", "warn")
    
    findings = []
    
    try:
        # Get CNAME records
        answers = dns.resolver.resolve(hostname, 'CNAME')
        cnames = [str(rdata).rstrip('.') for rdata in answers]
    except Exception:
        return []
    
    if not cnames:
        return []
    
    for cname in cnames:
        cname_lower = cname.lower()
        engine.print_status(f"  CNAME: {cname}", "info")
        
        for service, config in CLOUDS.items():
            if not any(pattern in cname_lower for pattern in config['cname_patterns']):
                continue
            
            engine.print_status(f"  ⚠️  Potential {service} takeover target!", "warn")
            
            # Try to verify by visiting the subdomain
            vulnerable = False
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                for proto in ['https', 'http']:
                    try:
                        url = f"{proto}://{hostname}"
                        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                        resp = urllib.request.urlopen(req, timeout=8, context=ctx)
                        body = resp.read(5000).decode('utf-8', errors='ignore').lower()
                        
                        for fingerprint in config['fingerprints']:
                            if fingerprint.lower() in body:
                                vulnerable = True
                                engine.print_status(f"  ✅ CONFIRMED TAKEOVER via {service}! (fingerprint: {fingerprint})", "error")
                                break
                    except urllib.error.HTTPError as e:
                        body = e.read(2000).decode('utf-8', errors='ignore').lower() if hasattr(e, 'read') else ''
                        for fingerprint in config['fingerprints']:
                            if fingerprint.lower() in body:
                                vulnerable = True
                                engine.print_status(f"  ✅ CONFIRMED TAKEOVER via {service}! (HTTP {e.code})", "error")
                                break
                    except Exception:
                        continue
                    
                    if vulnerable:
                        break
            except Exception:
                pass
            
            sev = "critical" if vulnerable else "medium"
            
            findings.append({
                "severity": sev,
                "title": f"{'✅ TAKEOVER' if vulnerable else 'Potential'} - {service} ({cname})",
                "description": f"Subdomain {hostname} points to {service} via CNAME ({cname}){' — CONFIRMED VULNERABLE!' if vulnerable else ''}",
                "detail": f"Subdomain: {hostname}\nCNAME: {cname}\nService: {service}\nStatus: {'⚠️  VULNERABLE - Can be claimed' if vulnerable else 'Potential - verify manually'}\n\nIf the target service is no longer using this subdomain, an attacker can claim it and host their own content.",
                "remediation": f"Remove the DNS CNAME record pointing to {service} if the service is no longer in use. Or re-register the service to reclaim the subdomain.",
                "raw_data": {"subdomain": hostname, "cname": cname, "service": service, "vulnerable": vulnerable}
            })
    
    return findings
