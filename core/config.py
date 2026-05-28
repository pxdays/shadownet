"""ShadowNet - Configuration Manager"""
import os
import json
import platform
from pathlib import Path

SYSTEM = platform.system().lower()
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "") or os.path.exists("/data/data/com.termux/files/usr/bin")

class Config:
    """Global configuration for ShadowNet"""
    
    VERSION = "1.0.0"
    AUTHOR = "pxdays"
    
    # Paths
    ROOT = Path(__file__).parent.parent
    OUTPUT_DIR = ROOT / "output"
    PLUGINS_DIR = ROOT / "plugins"
    WORDLISTS_DIR = ROOT / "wordlists"
    DB_PATH = ROOT / "shadownet.db"
    
    # Threading
    MAX_THREADS = 50
    TIMEOUT = 10
    
    # LLM (local)
    LLM_MODEL = "llama3.2:1b"  # light enough for any system
    LLM_ENABLED = False
    
    # Defaults
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    @classmethod
    def detect_platform(cls):
        """Detect platform capabilities"""
        info = {
            "system": SYSTEM,
            "is_termux": IS_TERMUX,
            "has_docker": False,
            "has_nmap": False,
            "python": platform.python_version(),
        }
        # Check for tools
        import shutil
        for tool in ["nmap", "docker", "curl", "wget", "dig", "whois", "nikto"]:
            info[f"has_{tool}"] = shutil.which(tool) is not None
        return info
    
    @classmethod
    def load(cls, path=None):
        """Load config from file"""
        if path is None:
            path = cls.ROOT / "config.json"
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return {}
    
    @classmethod
    def save(cls, config, path=None):
        """Save config to file"""
        if path is None:
            path = cls.ROOT / "config.json"
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)

