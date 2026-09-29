from typing import Any, Dict, List
from capx.core.analysis.base import BaseAnalyzer
from capx.logging_config import logger

class NetworkAnalyzer(BaseAnalyzer):
    """Interprets network connection facts for exposure and anomalies."""
    
    def __init__(self):
        # Initial set of ports that should raise a MONITOR flag if exposed to the world
        self.sensitive_ports = {3389, 445, 22, 23, 21, 1433, 3306}

    def analyze(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Analyzing network connection facts...")
        findings: List[Dict[str, Any]] = []
        
        if collected_data.get("status") not in ("success", "partial"):
            return {"status": "error", "message": "Cannot analyze invalid network data."}

        for conn in collected_data.get("data", []):
            pid = conn.get("pid", "UNKNOWN")
            status = conn.get("status")
            lport = conn.get("lport")
            laddr = conn.get("laddr", "")
            
            # 1. Identify listening services exposed to all interfaces
            if status == "LISTEN":
                if laddr and laddr.startswith("0.0.0.0"):
                    severity = "WARNING" if lport in self.sensitive_ports else "MONITOR"
                    findings.append({
                        "type": "OPEN_LISTENING_PORT",
                        "severity": severity,
                        "source": f"PID:{pid} | Port:{lport}",
                        "details": f"Process is listening on all network interfaces (0.0.0.0) via port {lport}."
                    })
                    
            # 2. Monitor Established Connections (Basic Heuristic)
            # In later phases, the Detection Engine will cross-reference this with known bad IPs.
            elif status == "ESTABLISHED":
                pass # Explicitly safe for Phase 3. 

        return {
            "status": "success",
            "analyzed_count": len(collected_data.get("data", [])),
            "findings_count": len(findings),
            "findings": findings
        }