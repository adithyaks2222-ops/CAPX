from typing import Any, Dict, List
from capx.logging_config import logger

class RecommendationEngine:
    """Generates actionable advice based on analysis and detection findings."""

    def __init__(self):
        # Maps internal finding types to human-readable action plans
        self.action_map = {
            "HIGH_CPU_PROCESS": "Consider terminating this process if it is not actively being used, or check for software updates.",
            "HIGH_MEMORY_PROCESS": "If system performance is degraded, restarting this application may free up consumed memory.",
            "MISSING_EXECUTABLE_PATH": "Verify if this is a legitimate Windows service. If unfamiliar, run a dedicated antivirus scan.",
            "OPEN_LISTENING_PORT": "Ensure the Windows Firewall is active. If external access isn't required, reconfigure the app to bind to localhost (127.0.0.1).",
            "SCRIPT_IN_STARTUP": "Review the script contents. If unauthorized, remove the corresponding registry autorun key.",
            "SUSPICIOUS_STARTUP_LOCATION": "Highly suspicious. Locate the target file and verify its signature. Remove the startup entry if malicious.",
            "CORRELATED_HIDDEN_LISTENER": "CRITICAL: Isolate the machine from the network immediately and terminate the offending PID."
        }

    def generate_recommendations(self, process_findings: List[Dict], network_findings: List[Dict], 
                                 startup_findings: List[Dict], detection_alerts: List[Dict]) -> Dict[str, Any]:
        logger.debug("Generating actionable recommendations...")
        recommendations: List[Dict[str, str]] = []
        
        all_issues = process_findings + network_findings + startup_findings + detection_alerts
        
        # Deduplicate recommendations for the same source to avoid spamming the user
        seen_targets = set()

        for issue in all_issues:
            issue_type = issue.get("type", "")
            target = issue.get("source", "Unknown Source")
            
            # Create a unique signature for this specific alert
            sig = f"{issue_type}_{target}"
            
            if issue_type in self.action_map and sig not in seen_targets:
                recommendations.append({
                    "priority": issue.get("severity", "MONITOR"),
                    "target": target,
                    "action": self.action_map[issue_type]
                })
                seen_targets.add(sig)

        # Sort recommendations by priority: CRITICAL first, then WARNING, then MONITOR
        priority_order = {"CRITICAL": 0, "WARNING": 1, "MONITOR": 2}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 3))

        return {
            "status": "success",
            "count": len(recommendations),
            "recommendations": recommendations
        }