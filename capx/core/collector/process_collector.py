import psutil
from typing import Any, Dict, List
from capx.core.collector.base import BaseCollector
from capx.logging_config import logger

class ProcessCollector(BaseCollector):
    """Collects raw facts about active Windows processes."""
    
    def collect(self) -> Dict[str, Any]:
        logger.debug("Collecting active process facts...")
        processes: List[Dict[str, Any]] = []
        
        # Prime the CPU percentage metric to avoid 0.0 readings
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        # Brief sleep for delta calculation
        import time
        time.sleep(0.5)

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'username']):
            try:
                info = proc.info
                processes.append({
                    "pid": info.get('pid'),
                    "name": info.get('name', 'UNKNOWN'),
                    "exe": info.get('exe'),
                    "cpu_percent": info.get('cpu_percent', 0.0),
                    "memory_percent": round(info.get('memory_percent', 0.0), 2),
                    "username": info.get('username')
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug(f"Unexpected error collecting process {proc.pid}: {e}")
                continue

        return {
            "status": "success",
            "count": len(processes),
            "data": processes
        }