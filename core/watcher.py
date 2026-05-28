"""ShadowNet - Watch Mode (Continuous Monitoring)"""
import time
import json
import threading
from datetime import datetime
from pathlib import Path

from .config import Config

class Watcher:
    """Monitors targets on a schedule and diffs results"""
    
    def __init__(self, engine):
        self.engine = engine
        self.watch_file = Config.ROOT / ".watcher_config.json"
        self.running = False
        self.thread = None
        self._load()
    
    def _load(self):
        if self.watch_file.exists():
            with open(self.watch_file) as f:
                self.config = json.load(f)
        else:
            self.config = {"targets": [], "interval": 3600}
    
    def _save(self):
        with open(self.watch_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def add_target(self, target, interval=3600):
        """Add a target to watch"""
        for t in self.config['targets']:
            if t['target'] == target:
                t['interval'] = interval
                self._save()
                return f"Updated watch interval for {target}"
        
        self.config['targets'].append({
            "target": target,
            "interval": interval,
            "last_scan": None,
            "created": datetime.now().isoformat()
        })
        self._save()
        return f"Now watching {target} (every {interval}s)"
    
    def remove_target(self, target):
        """Remove a target from watch"""
        self.config['targets'] = [t for t in self.config['targets'] if t['target'] != target]
        self._save()
        return f"Stopped watching {target}"
    
    def list_targets(self):
        """List all watched targets"""
        return self.config['targets']
    
    def start(self):
        """Start the watcher in a background thread"""
        if self.running:
            return "Watcher already running"
        
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
        return f"Watcher started ({len(self.config['targets'])} targets)"
    
    def stop(self):
        """Stop the watcher"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        return "Watcher stopped"
    
    def diff_findings(self, old_findings, new_findings):
        """Compare two sets of findings"""
        old_keys = {(f.get('title', ''), f.get('severity', '')) for f in old_findings}
        new_keys = {(f.get('title', ''), f.get('severity', '')) for f in new_findings}
        
        added = new_keys - old_keys
        removed = old_keys - new_keys
        
        return {
            "added": [f for f in new_findings if (f.get('title', ''), f.get('severity', '')) in added],
            "removed": [f for f in old_findings if (f.get('title', ''), f.get('severity', '')) in removed],
            "total_before": len(old_findings),
            "total_after": len(new_findings),
        }
    
    def _watch_loop(self):
        """Main watch loop"""
        from .utils import Colors, target_parse
        
        while self.running:
            now = datetime.now()
            
            for target_config in self.config['targets']:
                if not self.running:
                    break
                
                last = target_config.get('last_scan')
                interval = target_config.get('interval', 3600)
                
                should_scan = False
                if last is None:
                    should_scan = True
                else:
                    try:
                        last_time = datetime.fromisoformat(last)
                        if (now - last_time).total_seconds() >= interval:
                            should_scan = True
                    except Exception:
                        should_scan = True
                
                if should_scan:
                    try:
                        target = target_parse(target_config['target'])
                        self.engine.print_status(f"[WATCH] Scanning {target_config['target']}...", "info")
                        
                        from .database import Database
                        old_db = Database()
                        old_findings = old_db.get_findings()
                        
                        modules = list(self.engine.plugins.modules.keys())[:8]
                        self.engine.run_pipeline(target, modules)
                        
                        new_findings = self.engine.db.get_findings()
                        diff = self.diff_findings(old_findings, new_findings)
                        
                        if diff['added']:
                            self.engine.print_status(f"[WATCH] NEW FINDINGS on {target_config['target']}:", "error")
                            for f in diff['added'][:5]:
                                self.engine.print_status(f"  {f.get('severity','').upper()}: {f.get('title','')}", "error")
                        
                        target_config['last_scan'] = datetime.now().isoformat()
                        self._save()
                        
                    except Exception as e:
                        self.engine.print_status(f"[WATCH] Error scanning {target_config['target']}: {e}", "error")
            
            for _ in range(60):
                if not self.running:
                    break
                time.sleep(1)

