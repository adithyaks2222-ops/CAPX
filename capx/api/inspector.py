from typing import Any, Dict
from capx.core.collector.system_collector import SystemCollector
from capx.core.collector.process_collector import ProcessCollector
from capx.core.collector.network_collector import NetworkCollector
from capx.core.collector.startup_collector import StartupCollector

from capx.core.analysis.process_analyzer import ProcessAnalyzer
from capx.core.analysis.network_analyzer import NetworkAnalyzer
from capx.core.analysis.startup_analyzer import StartupAnalyzer

from capx.core.detection.anomaly_engine import AnomalyEngine

class InspectEngine:
    """Internal API orchestrator for the Inspect workflow."""
    
    def __init__(self):
        # 1. Collectors
        self.sys_collector = SystemCollector()
        self.proc_collector = ProcessCollector()
        self.net_collector = NetworkCollector()
        self.startup_collector = StartupCollector()
        
        # 2. Analyzers
        self.proc_analyzer = ProcessAnalyzer()
        self.net_analyzer = NetworkAnalyzer()
        self.startup_analyzer = StartupAnalyzer()
        
        # 3. Detection Engine
        self.anomaly_engine = AnomalyEngine()
        
    def run_full_inspection(self) -> Dict[str, Any]:
        """Executes the analysis pipeline and aggregates results."""
        
        # Phase 1-4: Collect & Analyze
        sys_data = self.sys_collector.collect()
        proc_analysis = self.proc_analyzer.analyze(self.proc_collector.collect())
        net_analysis = self.net_analyzer.analyze(self.net_collector.collect())
        startup_analysis = self.startup_analyzer.analyze(self.startup_collector.collect())
        
        # Phase 5: Detection / Correlation
        detection_alerts = self.anomaly_engine.correlate(
            process_analysis=proc_analysis,
            network_analysis=net_analysis,
            startup_analysis=startup_analysis
        )
        
        return {
            "system_facts": sys_data,
            "process_findings": proc_analysis,
            "network_findings": net_analysis,
            "startup_findings": startup_analysis,
            "detection_alerts": detection_alerts
        }