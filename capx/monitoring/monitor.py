import time
from typing import Any, Dict
from capx.api.inspector import InspectEngine
from capx.config import config
from capx.logging_config import logger

class MonitorEngine:
    """Continuously monitors system state and triggers alerts on risk threshold breaches."""
    
    def __init__(self, interval_seconds: int = 15):
        self.interval = interval_seconds
        self.engine = InspectEngine()
        self.alert_thresholds = ["WARNING", "CRITICAL"]

    def start_monitoring(self):
        logger.info(f"Starting continuous monitoring mode (Interval: {self.interval}s)...")
        print(f"[*] CAPX Continuous Monitoring Active. (Scan interval: {self.interval} seconds)")
        print("[*] Press CTRL+C to stop monitoring.\n")
        
        try:
            while True:
                # 1. Run the silent inspection pipeline
                results = self.engine.run_full_inspection()
                risk = results.get("risk_assessment", {})
                band = risk.get("band", "SAFE")
                score = risk.get("score", 0)
                
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                
                # 2. Check if the risk band breaches our alert threshold
                if band in self.alert_thresholds:
                    print(f"[{timestamp}] [ALERT] System Risk elevated to {band} (Score: {score}/100)")
                    
                    # Output high-priority recommendations to the console
                    recs = results.get("recommendations", {}).get("recommendations", [])
                    for r in recs:
                        if r["priority"] in self.alert_thresholds:
                            print(f"    -> Action Required [{r['priority']}]: {r['target']}")
                else:
                    # Print a low-noise heartbeat for safe states
                    print(f"[{timestamp}] [OK] System health stable. Risk: {band} ({score}/100)")
                    
                # 3. Wait for the next cycle
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            print("\n[*] Continuous monitoring stopped by user.")
            logger.info("Monitoring mode terminated by user.")