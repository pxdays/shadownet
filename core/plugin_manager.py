"""ShadowNet - Plugin System"""
import os
import sys
import importlib
import importlib.util
from pathlib import Path

class PluginManager:
    """Loads and manages modules and plugins"""
    
    def __init__(self):
        self.modules = {}
        self.plugins = {}
    
    def _load_module(self, filepath):
        """Load a Python file as a module with proper import context"""
        name = filepath.stem
        
        # Get the relative package path
        from .config import Config
        root = Config.ROOT
        
        # Compute package path relative to root
        rel_path = filepath.relative_to(root)
        parts = list(rel_path.parts[:-1])  # exclude the filename
        
        # Build package name (e.g., 'modules.recon')
        pkg = '.'.join(parts) if parts else '__main__'
        
        # Add root to sys.path so absolute imports work
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        
        try:
            spec = importlib.util.spec_from_file_location(f"{pkg}.{name}" if pkg else name, filepath)
            if spec is None:
                return None
            
            mod = importlib.util.module_from_spec(spec)
            mod.__package__ = pkg
            
            # Set __path__ for package-style loading
            if parts:
                mod.__path__ = [str(filepath.parent)]
            
            spec.loader.exec_module(mod)
            return mod
        except Exception as e:
            # Fallback: simple exec
            try:
                namespace = {'__file__': str(filepath), '__name__': name, '__package__': pkg}
                # Add core to namespace for imports
                import core.utils as core_utils
                import core.config as core_config
                namespace['core'] = type(sys)('core')
                namespace['core'].utils = core_utils
                namespace['core'].config = core_config
                
                with open(filepath) as f:
                    exec(f.read(), namespace)
                if 'run' in namespace:
                    class Wrapper:
                        pass
                    w = Wrapper()
                    for k, v in namespace.items():
                        if not k.startswith('_') or k == '__doc__':
                            setattr(w, k, v)
                    return w
            except Exception:
                raise e
    
    def discover_modules(self):
        """Auto-discover built-in modules"""
        from .config import Config
        
        module_dirs = [
            Config.ROOT / "modules" / "recon",
            Config.ROOT / "modules" / "scanning",
            Config.ROOT / "modules" / "vuln",
            Config.ROOT / "modules" / "exploit",
            Config.ROOT / "modules" / "harvest",
        ]
        
        for mod_dir in module_dirs:
            if not mod_dir.exists():
                continue
            for f in sorted(mod_dir.glob("*.py")):
                if f.name.startswith("_"):
                    continue
                module_name = f.stem
                try:
                    mod = self._load_module(f)
                    if mod and hasattr(mod, 'run'):
                        self.modules[module_name] = mod
                except Exception as e:
                    pass
        
        return self.modules
    
    def discover_plugins(self):
        """Load user plugins from plugins directory"""
        from .config import Config
        
        plugins_dir = Config.PLUGINS_DIR
        if not plugins_dir.exists():
            return self.plugins
        
        for f in plugins_dir.glob("*.py"):
            if f.name.startswith("_"):
                continue
            try:
                mod = self._load_module(f)
                if mod and hasattr(mod, 'run'):
                    self.plugins[f.stem] = mod
            except Exception:
                pass
        
        return self.plugins
    
    def get_module_info(self, module_name):
        """Get metadata about a module"""
        mod = self.modules.get(module_name) or self.plugins.get(module_name)
        if not mod:
            return None
        
        return {
            "name": module_name,
            "description": getattr(mod, 'DESCRIPTION', 'No description'),
            "author": getattr(mod, 'AUTHOR', 'Unknown'),
            "version": getattr(mod, 'VERSION', '1.0'),
            "requires": getattr(mod, 'REQUIRES', []),
            "timeout": getattr(mod, 'TIMEOUT', 300),
        }

