from typing import Any, Dict, List
from capx.core.analysis.base import BaseAnalyzer
from capx.logging_config import logger

class StartupAnalyzer(BaseAnalyzer):
    """Interprets startup facts to identify suspicious persistence mechanisms."""
    
    def __init__(self):
        # File extensions highly unusual for standard startup programs
        self.script_extensions = {'.bat', '.ps1', '.vbs', '.cmd', '.js', '.vbe'}

    def analyze(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Analyzing startup items for persistence indicators...")
        findings: List[Dict[str, Any]] = []
        
        if collected_data.get("status") != "success":
            return {"status": "error", "message": "Cannot analyze invalid startup data."}

        for item in collected_data.get("data", []):
            target = str(item.get("target", "")).lower()
            name = item.get("name", "UNKNOWN")
            
            # 1. Detect Scripts in Startup
            if any(ext in target for ext in self.script_extensions):
                findings.append({
                    "type": "SCRIPT_IN_STARTUP",
                    "severity": "WARNING",
                    "source": f"Registry: {name}",
                    "details": f"A script file is configured to run on boot: {item.get('target')}"
                })
                
            # 2. Detect execution from temporary or unusual directories
            if "appdata\\local\\temp" in target or "programdata" in target:
                findings.append({
                    "type": "SUSPICIOUS_STARTUP_LOCATION",
                    "severity": "WARNING",
                    "source": f"Registry: {name}",
                    "details": f"Program executing from a temporary/shared directory: {item.get('target')}"
                })

        return {
            "status": "success",
            "analyzed_count": len(collected_data.get("data", [])),
            "findings_count": len(findings),
            "findings": findings
        }