from typing import Any, Dict, List
from capx.logging_config import logger

class AnomalyEngine:
    """Correlates individual analysis findings to detect multi-vector behavioral anomalies."""
    
    def correlate(self, process_analysis: Dict, network_analysis: Dict, startup_analysis: Dict) -> Dict[str, Any]:
        logger.debug("Correlating indicators in the Detection Engine...")
        alerts: List[Dict[str, Any]] = []
        
        proc_findings = process_analysis.get("findings", [])
        net_findings = network_analysis.get("findings", [])
        
        # Extract PIDs of processes that have missing executable paths
        sus_pids = set()
        for p in proc_findings:
            if p["type"] == "MISSING_EXECUTABLE_PATH":
                try:
                    # Parse PID from source string "PID:1234 (Name)"
                    pid_str = p["source"].split(" ")[0].split(":")[1]
                    sus_pids.add(pid_str)
                except Exception:
                    continue
                    
        # Rule 1: The "Hidden Listener"
        # Correlates a missing executable path WITH an open network listening port
        for n in net_findings:
            if n["type"] == "OPEN_LISTENING_PORT":
                try:
                    # Parse PID from source string "PID:1234 | Port:80"
                    net_pid_str = n["source"].split(" | ")[0].split(":")[1]
                    
                    if net_pid_str in sus_pids:
                        alerts.append({
                            "type": "CORRELATED_HIDDEN_LISTENER",
                            "severity": "CRITICAL",
                            "source": f"PID:{net_pid_str}",
                            "details": "A process with no accessible executable path is listening on an open network port."
                        })
                except Exception:
                    continue

        return {
            "status": "success",
            "alerts_count": len(alerts),
            "alerts": alerts
        }