"""ShadowNet - Orchestration Engine"""
import sys
import time
import json
import signal
import threading
from datetime import datetime
from pathlib import Path

from .config import Config
from .database import Database
from .plugin_manager import PluginManager
from .utils import Colors, banner, target_parse, is_ip, is_domain, save_result, enable_windows_ansi

class ShadowEngine:
    """Main orchestration engine"""
    
    def __init__(self):
        enable_windows_ansi()
        self.db = Database()
        self.plugins = PluginManager()
        self.running = True
        self.current_scan = None
        self.findings = []
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._handle_sigint)
    
    def _handle_sigint(self, sig, frame):
        print(f"\n{Colors.YELLOW}[!] Interrupted by user. Finishing current module...{Colors.RESET}")
        self.running = False
    
    def print_banner(self):
        print(banner())
    
    def print_status(self, msg, status="info"):
        """Print a status message"""
        icons = {
            "info": f"{Colors.BLUE}[*]{Colors.RESET}",
            "ok": f"{Colors.GREEN}[+]{Colors.RESET}",
            "warn": f"{Colors.YELLOW}[!]{Colors.RESET}",
            "error": f"{Colors.RED}[-]{Colors.RESET}",
            "finding": f"{Colors.RED}[!]{Colors.RESET}",
        }
        icon = icons.get(status, icons['info'])
        print(f"  {icon} {msg}")
    
    def prompt_target(self):
        """Interactive target input"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║          TARGET INPUT                 ║{Colors.RESET}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════╝{Colors.RESET}")
        print(f"\n{Colors.DIM}Examples: example.com | 192.168.1.1 | https://target.com/admin{Colors.RESET}")
        
        target = input(f"\n{Colors.GREEN}⚡ Target > {Colors.RESET}").strip()
        while not target:
            target = input(f"{Colors.GREEN}⚡ Target > {Colors.RESET}").strip()
        
        parsed = target_parse(target)
        print(f"\n  {Colors.CYAN}Target:{Colors.RESET}       {parsed['hostname']}")
        print(f"  {Colors.CYAN}Protocol:{Colors.RESET}     {parsed['protocol']}")
        print(f"  {Colors.CYAN}Port:{Colors.RESET}         {parsed['port']}")
        print(f"  {Colors.CYAN}Type:{Colors.RESET}         {'IP' if is_ip(parsed['hostname']) else 'Domain'}")
        
        return parsed
    
    def select_modules(self):
        """Let user choose modules interactively"""
        all_modules = list(self.plugins.modules.keys())
        
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║        MODULE SELECTION              ║{Colors.RESET}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════╝{Colors.RESET}")
        
        print(f"\n  {Colors.DIM}Available modules:{Colors.RESET}")
        categories = {
            "recon": [m for m in all_modules if any(d in str(m) for d in ['recon', 'subdomain', 'dns', 'whois'])],
            "scanning": [m for m in all_modules if any(d in str(m) for d in ['port', 'scan', 'service', 'dir'])],
            "vuln": [m for m in all_modules if any(d in str(m) for d in ['vuln', 'cve', 'cors', 'sqli'])],
            "exploit": [m for m in all_modules if any(d in str(m) for d in ['exploit', 'shell', 'payload'])],
            "harvest": [m for m in all_modules if any(d in str(m) for d in ['harvest', 'secret', 'extract'])],
        }
        
        for cat, mods in categories.items():
            if mods:
                print(f"    {Colors.GREEN}{cat.upper():10s}{Colors.RESET} {', '.join(mods)}")
        
        print(f"\n  {Colors.DIM}Default: All modules (full scan){Colors.RESET}")
        choice = input(f"\n{Colors.GREEN}⚡ Modules (all/recon/scan/vuln/exploit/harvest) [all] > {Colors.RESET}").strip().lower()
        
        if choice == 'all' or not choice:
            return all_modules
        elif choice == 'recon':
            return categories['recon']
        elif choice == 'scan':
            return categories['scanning']
        elif choice == 'vuln':
            return categories['vuln']
        elif choice == 'exploit':
            return categories['exploit']
        elif choice == 'harvest':
            return categories['harvest']
        else:
            return all_modules
    
    def run_module(self, module_name, target_parsed):
        """Execute a single module"""
        mod = self.plugins.modules.get(module_name) or self.plugins.plugins.get(module_name)
        if not mod:
            self.print_status(f"Module '{module_name}' not found", "error")
            return []
        
        module_info = self.plugins.get_module_info(module_name)
        timeout = module_info.get('timeout', 300) if module_info else 300
        
        self.print_status(f"Running {module_name}...", "info")
        
        # Get target ID from DB
        target_id = self.db.add_target(target_parsed['hostname'])
        scan_id = self.db.start_scan(target_id, module_name)
        
        findings = []
        try:
            result = mod.run(target_parsed, self)
            if result:
                for finding in result:
                    finding['scan_id'] = scan_id
                    findings.append(finding)
                
                # Save to DB
                for f in findings:
                    self.db.add_finding(
                        scan_id=scan_id,
                        severity=f.get('severity', 'info'),
                        title=f.get('title', 'Unknown'),
                        description=f.get('description', ''),
                        detail=f.get('detail', ''),
                        remediation=f.get('remediation', ''),
                        cve_id=f.get('cve_id', ''),
                        cvss=f.get('cvss', 0.0),
                        raw_data=f.get('raw_data')
                    )
                
                # Save to file
                save_result(target_parsed['hostname'], module_name, findings)
                
                # Print findings
                for f in findings:
                    sev = f.get('severity', 'info')
                    title = f.get('title', '')
                    sev_color = {
                        'critical': Colors.RED, 'high': Colors.RED,
                        'medium': Colors.YELLOW, 'low': Colors.BLUE,
                        'info': Colors.DIM
                    }.get(sev, Colors.DIM)
                    
                    if sev in ('critical', 'high', 'medium'):
                        self.print_status(f"[{sev.upper()}] {title}", "finding")
                    else:
                        self.print_status(f"[{sev.upper()}] {title}", "info")
                
                self.db.complete_scan(scan_id, len(findings), f"Found {len(findings)} issues")
                
        except Exception as e:
            self.print_status(f"{module_name} failed: {e}", "error")
            self.db.complete_scan(scan_id, 0, f"Error: {e}")
        
        return findings
    
    def run_pipeline(self, target_parsed, modules):
        """Run the full pipeline"""
        self.findings = []
        total = len(modules)
        
        self.print_status(f"Starting pipeline: {total} modules", "info")
        print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}")
        
        for i, module_name in enumerate(modules, 1):
            if not self.running:
                break
            
            print(f"\n  {Colors.CYAN}[{i}/{total}] {module_name}{Colors.RESET}")
            
            findings = self.run_module(module_name, target_parsed)
            self.findings.extend(findings)
        
        # Summary
        self._print_summary()
        
        # Generate report
        self._generate_report(target_parsed)
    
    def _print_summary(self):
        """Print scan summary"""
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║           SCAN COMPLETE              ║{Colors.RESET}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════╝{Colors.RESET}")
        
        sev_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in self.findings:
            sev_count[f.get('severity', 'info')] = sev_count.get(f.get('severity', 'info'), 0) + 1
        
        print(f"\n  {Colors.RED}Critical: {sev_count['critical']}{Colors.RESET}")
        print(f"  {Colors.RED}High:     {sev_count['high']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Medium:   {sev_count['medium']}{Colors.RESET}")
        print(f"  {Colors.BLUE}Low:      {sev_count['low']}{Colors.RESET}")
        print(f"  {Colors.DIM}Info:     {sev_count['info']}{Colors.RESET}")
        print(f"  {Colors.GREEN}Total:    {len(self.findings)}{Colors.RESET}")
    
    def _generate_report(self, target_parsed):
        """Generate HTML report"""
        from .report import ReportGenerator
        report = ReportGenerator(target_parsed, self.findings, self.db)
        path = report.generate()
        if path:
            self.print_status(f"Report saved: {path}", "ok")
    
    def interactive(self):
        """Full interactive session"""
        self.discover()
        self.print_banner()
        
        target = self.prompt_target()
        
        # Quick scan or full scan prompt
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║        SCAN MODE                     ║{Colors.RESET}")
        print(f"{Colors.CYAN}╚══════════════════════════════════════╝{Colors.RESET}")
        print(f"\n  {Colors.DIM}1.{Colors.RESET} {Colors.GREEN}Quick Scan{Colors.RESET}   — recon + common ports + basic vulns")
        print(f"  {Colors.DIM}2.{Colors.RESET} {Colors.GREEN}Full Audit{Colors.RESET}   — everything (deep scan)")
        print(f"  {Colors.DIM}3.{Colors.RESET} {Colors.GREEN}Custom{Colors.RESET}        — pick your modules")
        
        choice = input(f"\n{Colors.GREEN}⚡ Mode [1] > {Colors.RESET}").strip()
        
        all_mods = list(self.plugins.modules.keys())
        
        if choice == '2':
            modules = all_mods
        elif choice == '3':
            modules = self.select_modules()
        else:
            # Quick: recon + port scan + common vulns
            keywords = ['subdomain', 'dns', 'port', 'cve', 'tech', 'whois']
            modules = [m for m in all_mods if any(k.lower() in m.lower() for k in keywords)]
            if not modules:
                modules = all_mods[:5]
        
        if not modules:
            self.print_status("No modules selected!", "error")
            return
        
        print(f"\n  {Colors.DIM}Modules to run: {len(modules)}{Colors.RESET}")
        for m in modules:
            print(f"    {Colors.CYAN}→{Colors.RESET} {m}")
        
        confirm = input(f"\n{Colors.GREEN}⚡ Start scan? [Y/n] > {Colors.RESET}").strip().lower()
        if confirm not in ('', 'y', 'yes'):
            self.print_status("Scan cancelled", "warn")
            return
        
        start = time.time()
        self.run_pipeline(target, modules)
        elapsed = time.time() - start
        
        print(f"\n  {Colors.DIM}{'─' * 50}{Colors.RESET}")
        self.print_status(f"Completed in {elapsed:.1f}s", "ok")
    
    def discover(self):
        """Discover all modules"""
        self.print_status("Loading modules...", "info")
        self.plugins.discover_modules()
        self.plugins.discover_plugins()
        self.print_status(f"Loaded {len(self.plugins.modules)} modules + {len(self.plugins.plugins)} plugins", "ok")

