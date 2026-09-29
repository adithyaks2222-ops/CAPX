from typing import Any, Dict, List
from capx.core.analysis.base import BaseAnalyzer
from capx.logging_config import logger

class ProcessAnalyzer(BaseAnalyzer):
    """Interprets process facts for resource anomalies and basic heuristics."""
    
    def __init__(self, cpu_threshold: float = 25.0, mem_threshold: float = 20.0):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold

    def analyze(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("Analyzing process facts...")
        findings: List[Dict[str, Any]] = []
        
        if collected_data.get("status") != "success":
            return {"status": "error", "message": "Cannot analyze invalid process data."}

        for proc in collected_data.get("data", []):
            pid = proc.get("pid")
            name = proc.get("name")
            
            # Identify Resource Heaviness
            if proc.get("cpu_percent", 0.0) > self.cpu_threshold:
                findings.append({
                    "type": "HIGH_CPU_PROCESS",
                    "severity": "WARNING",
                    "source": f"PID:{pid} ({name})",
                    "details": f"Consuming {proc.get('cpu_percent')}% CPU."
                })

            if proc.get("memory_percent", 0.0) > self.mem_threshold:
                findings.append({
                    "type": "HIGH_MEMORY_PROCESS",
                    "severity": "WARNING",
                    "source": f"PID:{pid} ({name})",
                    "details": f"Consuming {proc.get('memory_percent')}% Memory."
                })
                
            # Basic OS Heuristic: User-space processes > PID 4 without an executable path
            if not proc.get("exe") and pid > 4:
                # We do not declare this malware, just an anomaly to MONITOR
                findings.append({
                    "type": "MISSING_EXECUTABLE_PATH",
                    "severity": "MONITOR",
                    "source": f"PID:{pid} ({name})",
                    "details": "Process has an inaccessible or missing executable path."
                })

        return {
            "status": "success",
            "analyzed_count": len(collected_data.get("data", [])),
            "findings_count": len(findings),
            "findings": findings
        }