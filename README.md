# ShadowNet — Autonomous Red Team Engine

> Built by **pxdays** (15) | CLI tools developer | Ethical hacking & security automation

**One command. Full recon. Instant reports.** ShadowNet is a complete penetration testing and reconnaissance framework that replaces 8+ separate tools with one seamless pipeline.

## 🚀 Quick Start

```bash
# Linux / macOS / Termux
bash install.sh

# Basic scan
shadownet scan example.com

# Quick recon (subdomains + ports + tech)
shadownet quick example.com

# Interactive mode (guided)
shadownet interactive
```

## 🎯 Features

### Reconnaissance
- **Subdomain Enumeration** — DNS brute-force (50+ wordlist) + Certificate Transparency (crt.sh)
- **DNS Records** — A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA + zone transfer check
- **WHOIS Lookup** — Registration data, expiry dates, registrar info
- **Technology Detection** — Server, framework, CMS, all security headers
- **Port Scanning** — 60+ common ports with banner grabbing + service fingerprinting
- **Directory Bruteforce** — 100+ paths, admin panels, config files, .env, .git

### Vulnerability Detection
- **CVE Scanner** — Matches service versions against known vulnerabilities (auto-updates from CVE database)
- **SQL Injection** — Tests parameters with payload injection + error detection
- **Secret Scanner** — Finds API keys, tokens, passwords in JS/HTML (30+ patterns)
- **Auto-Exploit** — Admin panel detection, default credential checks

### Advanced
- **Watch Mode** — Continuous monitoring with diff alerts
- **Stealth Mode** — Random delays, proxy rotation, dynamic user-agents
- **HTML Reports** — Professional pentest-grade reports with risk scoring
- **Local LLM** — AI-powered report writing via Ollama (optional)
- **Cross-Platform** — Windows, Linux, macOS, Android (Termux)

### Report Example
A professional HTML report with:
- Risk score and severity breakdown
- Executive summary (with LLM)
- Complete findings with CVEs, CVSS scores
- Remediation steps for each finding
- Scan history and timeline

## 📦 Installation

### Linux / macOS / Termux (Android)
```bash
bash install.sh
```

### Windows
```
Double-click install.bat
```

### Manual
```bash
git clone https://github.com/pxdays/shadownet
cd shadownet
pip install dnspython
python shadownet.py interactive
```

## 🧩 Module System

```
shadownet --modules subdomain_scanner port_scanner tech_detect
```

### Built-in modules:

| Module | Category | Description |
|---|---|---|
| `subdomain_scanner` | Recon | DNS brute-force + crt.sh |
| `dns_enum` | Recon | All record types + zone transfer |
| `whois_lookup` | Recon | Domain registration data |
| `tech_detect` | Recon | Server detection + security headers |
| `port_scanner` | Recon | TCP port scanning |
| `directory_scanner` | Recon | Path brute-force |
| `service_detect` | Scanning | Advanced fingerprinting |
| `cve_scanner` | Vuln | CVE matching |
| `sqli_check` | Vuln | SQL injection detection |
| `auto_exploit` | Exploit | Admin panels + default creds |
| `secret_scanner` | Harvest | API keys + tokens + passwords |

### Custom plugins
Drop a `.py` file with a `run(target, engine)` function into the `plugins/` folder. It auto-loads on next start.

## 🔒 Use Cases

- **Bug Bounty Hunters** — Quick recon before manual testing. Save 3+ hours per target.
- **Penetration Testers** — First-pass automation. Focus on the interesting findings.
- **Sysadmins** — Weekly infrastructure scans. Watch mode alerts you to changes.
- **Security Students** — See the full pipeline in action. Learn by doing.
- **Freelancers** — Generate professional reports to deliver to clients.

## ⚙️ Requirements

- Python 3.7+
- `dnspython` (optional — for subdomain/DNS modules)

## ⚠️ Legal

ShadowNet is for **authorized testing only**. Use only on systems you own or have explicit permission to test. The author is not responsible for misuse.

## 📬 Payment

One-time purchase: **$20 USD** via:
- Litecoin (LTC)
- Steam Gift Card
- Amazon Gift Card

Full source code included. No DRM. No subscriptions. Own it forever.

---

*Built with too much tea and zero sleep — pxdays, 2026*
