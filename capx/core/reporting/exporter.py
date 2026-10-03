import json
import os
import time
from typing import Dict, Any
from capx.logging_config import logger

class ReportExporter:
    """Handles exporting inspection results to disk for compliance and external analysis."""
    
    def __init__(self):
        # Creates a 'reports' directory in the root folder if it doesn't exist
        self.reports_dir = os.path.join(os.getcwd(), 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)

    def export_json(self, data: Dict[str, Any]) -> str:
        """Saves the full telemetry and findings dictionary to a timestamped JSON file."""
        logger.debug("Exporting inspection results to JSON...")
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"capx_report_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Report successfully exported to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to export report: {e}")
            return ""