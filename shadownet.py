#!/usr/bin/env python3
"""ShadowNet - Autonomous Red Team Engine v1.0"""
import sys
import os
import argparse
import signal

# Add root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import ShadowEngine
from core.utils import Colors, enable_windows_ansi
from core.watcher import Watcher
from core.stealth import StealthEngine
from core.llm import LLMEngine

VERSION = "1.0.0"

def main():
    enable_windows_ansi()
    
    parser = argparse.ArgumentParser(
        description="ShadowNet - Autonomous Red Team Engine",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="""shadownet <command> [<args>]

Commands:
  scan <target>       Full scan against a target
  quick <target>      Quick recon scan (subdomains + ports + tech)
  stealth <target>    Stealth scan (slow + randomized)
  watch <target>      Add target to continuous monitoring
  report <target>     Generate HTML report from scan data
  interactive         Launch interactive mode
  modules             List all available modules
  stats               Show database statistics
  watch-list          List monitored targets
  watch-stop          Stop continuous monitoring  
  version             Show version
""")
    
    parser.add_argument('command', nargs='?', help='Command to run')
    parser.add_argument('target', nargs='?', help='Target domain/IP/URL')
    parser.add_argument('--modules', '-m', nargs='+', help='Specific modules to run')
    parser.add_argument('--output', '-o', help='Output directory')
    parser.add_argument('--threads', '-t', type=int, default=30, help='Max threads')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--stealth', '-s', action='store_true', help='Enable stealth mode')
    parser.add_argument('--llm', action='store_true', help='Enable LLM report writing')
    
    args = parser.parse_args()
    
    # Initialize engine
    engine = ShadowEngine()
    engine.discover()
    
    # Optional features
    if args.stealth:
        engine.stealth = StealthEngine(enabled=True)
        engine.print_status("Stealth mode enabled", "info")
    
    if args.llm:
        engine.llm = LLMEngine()
        if engine.llm.available:
            engine.print_status(f"LLM engine online ({engine.llm.model})", "ok")
        else:
            engine.print_status("LLM unavailable (install Ollama)", "warn")
    
    # Watcher
    watcher = Watcher(engine)
    
    if not args.command or args.command == 'interactive':
        engine.interactive()
    
    elif args.command == 'scan':
        if not args.target:
            print(f"{Colors.RED}[-] Usage: shadownet scan <target>{Colors.RESET}")
            return
        engine.print_banner()
        from core.utils import target_parse
        target = target_parse(args.target)
        if args.modules:
            modules = [m for m in args.modules if m in engine.plugins.modules]
        else:
            modules = list(engine.plugins.modules.keys())
        engine.run_pipeline(target, modules)
    
    elif args.command == 'quick':
        if not args.target:
            print(f"{Colors.RED}[-] Usage: shadownet quick <target>{Colors.RESET}")
            return
        engine.print_banner()
        from core.utils import target_parse
        target = target_parse(args.target)
        keywords = ['subdomain', 'dns', 'port', 'tech', 'whois']
        modules = [m for m in engine.plugins.modules if any(k in m.lower() for k in keywords)]
        if not modules:
            modules = list(engine.plugins.modules.keys())[:5]
        engine.run_pipeline(target, modules)
    
    elif args.command == 'stealth':
        if not args.target:
            print(f"{Colors.RED}[-] Usage: shadownet stealth <target>{Colors.RESET}")
            return
        engine.stealth = StealthEngine(enabled=True)
        engine.print_banner()
        engine.print_status("STEALTH MODE ACTIVE — randomized delays, rotating UAs", "warn")
        from core.utils import target_parse
        target = target_parse(args.target)
        modules = list(engine.plugins.modules.keys())
        engine.run_pipeline(target, modules)
    
    elif args.command == 'watch':
        if not args.target:
            print(f"{Colors.RED}[-] Usage: shadownet watch <target>{Colors.RESET}")
            return
        msg = watcher.add_target(args.target)
        engine.print_status(msg, "ok")
        watcher.start()
        engine.print_status("Watch mode started in background", "info")
    
    elif args.command == 'watch-list':
        targets = watcher.list_targets()
        if not targets:
            print(f"{Colors.DIM}  No targets being monitored{Colors.RESET}")
        else:
            print(f"\n{Colors.CYAN}Watched Targets:{Colors.RESET}\n")
            for t in targets:
                last = t.get('last_scan', 'never')
                print(f"  {Colors.GREEN}{t['target']:30s}{Colors.RESET} interval: {t['interval']}s  last: {last[:19] if last != 'never' else 'never'}")
        print()
    
    elif args.command == 'watch-stop':
        msg = watcher.stop()
        engine.print_status(msg, "info")
    
    elif args.command == 'report':
        if not args.target:
            print(f"{Colors.RED}[-] Usage: shadownet report <target>{Colors.RESET}")
            return
        from core.utils import target_parse
        target = target_parse(args.target)
        findings = engine.db.get_findings()
        if findings:
            from core.report import ReportGenerator
            report = ReportGenerator(target, findings, engine.db)
            path = report.generate()
            engine.print_status(f"Report saved: {path}", "ok")
        else:
            engine.print_status("No findings in database. Run a scan first.", "warn")
    
    elif args.command == 'modules':
        print(f"\n{Colors.CYAN}Available Modules:{Colors.RESET}\n")
        cats = {'recon': [], 'scanning': [], 'vuln': [], 'exploit': [], 'harvest': []}
        for name, mod in sorted(engine.plugins.modules.items()):
            desc = getattr(mod, 'DESCRIPTION', 'No description')
            # Determine category from module path
            try:
                mod_file = getattr(mod, '__file__', '')
                cat = 'recon'
                if '/scanning/' in mod_file: cat = 'scanning'
                elif '/vuln/' in mod_file: cat = 'vuln'
                elif '/exploit/' in mod_file: cat = 'exploit'
                elif '/harvest/' in mod_file: cat = 'harvest'
                if cat in cats:
                    cats[cat].append((name, desc))
                else:
                    cats['recon'].append((name, desc))
            except Exception:
                cats['recon'].append((name, desc))
        
        for cat, mods in cats.items():
            if mods:
                print(f"  {Colors.GREEN}{cat.upper()}{Colors.RESET}")
                for name, desc in mods:
                    print(f"    {Colors.CYAN}→{Colors.RESET} {name:25s} {desc}")
                print()
    
    elif args.command == 'stats':
        stats = engine.db.get_stats()
        print(f"\n{Colors.CYAN}Database Statistics:{Colors.RESET}")
        print(f"  {'Targets:':15s} {stats['total_targets']}")
        print(f"  {'Scans:':15s} {stats['total_scans']}")
        print(f"  {'Findings:':15s} {stats['total_findings']}")
        print(f"  {Colors.RED}{'Critical:':15s} {stats['critical']}{Colors.RESET}")
        print(f"  {Colors.RED}{'High:':15s} {stats['high']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}{'Medium:':15s} {stats['medium']}{Colors.RESET}")
        print(f"  {Colors.BLUE}{'Low:':15s} {stats['low']}{Colors.RESET}")
        print(f"  {Colors.DIM}{'Info:':15s} {stats['info']}{Colors.RESET}")
        print()
    
    elif args.command == 'version':
        print(f"ShadowNet v{VERSION}")
        print(f"Author: pxdays")
        print(f"Platform: {sys.platform}")
        print(f"Python: {sys.version.split()[0]}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}[-] Fatal: {e}{Colors.RESET}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()

