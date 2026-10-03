from typing import Any, Dict, List
from capx.config import config
from capx.logging_config import logger

class RiskScorer:
    """Calculates a structured risk score based on analysis and detection findings."""
    
    def __init__(self):
        # Base point weights for different severity levels
        self.weights = {
            "MONITOR": 5,
            "WARNING": 15,
            "CRITICAL": 35
        }

    def calculate_risk(self, process_findings: List[Dict], network_findings: List[Dict], 
                       startup_findings: List[Dict], detection_alerts: List[Dict]) -> Dict[str, Any]:
        logger.debug("Calculating overall system risk score...")
        total_score = 0
        
        # Aggregate all findings into a single list
        all_issues = process_findings + network_findings + startup_findings + detection_alerts
        
        # NEW: Filter out known false positives (Tuning)
        valid_issues = []
        for item in all_issues:
            source = str(item.get("source", ""))
            # Whitelist specific normal behaviors to prevent alarm fatigue
            if "PID:0" in source or "capx.exe" in source or "Port:445" in source:
                continue
            valid_issues.append(item)
        
        for item in valid_issues:
            severity = item.get("severity", "MONITOR")
            total_score += self.weights.get(severity, 0)

        # The maximum possible risk score is 100
        final_score = min(total_score, 100)
        
        # Determine the Risk Band strictly based on the defined system boundaries
        if final_score <= config.RISK_SAFE_MAX:
            band = "SAFE"
        elif final_score <= config.RISK_MONITOR_MAX:
            band = "MONITOR"
        elif final_score <= config.RISK_WARNING_MAX:
            band = "WARNING"
        else:
            band = "CRITICAL"

        return {
            "status": "success",
            "score": final_score,
            "band": band,
            "total_issues_evaluated": len(valid_issues) # Only count what we evaluated
        }