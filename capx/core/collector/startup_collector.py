import winreg
from typing import Any, Dict, List
from capx.core.collector.base import BaseCollector
from capx.logging_config import logger

class StartupCollector(BaseCollector):
    """Collects raw facts about Windows autorun and startup configurations."""
    
    def collect(self) -> Dict[str, Any]:
        logger.debug("Collecting Windows startup items...")
        startup_items: List[Dict[str, Any]] = []

        # Core Windows Run keys used for persistence
        registry_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hkey_root, subkey_path in registry_targets:
            try:
                # Attempt to open the registry key strictly in Read-Only mode
                with winreg.OpenKey(hkey_root, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    
                    for i in range(num_values):
                        name, value, _ = winreg.EnumValue(key, i)
                        root_name = "HKLM" if hkey_root == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                        
                        startup_items.append({
                            "name": name,
                            "target": value,
                            "location": f"{root_name}\\{subkey_path}"
                        })
                        
            except FileNotFoundError:
                # Key does not exist, which is normal on some Windows builds
                continue
            except PermissionError:
                logger.debug(f"Permission denied reading registry key {subkey_path}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error reading registry {subkey_path}: {e}")
                continue

        return {
            "status": "success",
            "count": len(startup_items),
            "data": startup_items
        }