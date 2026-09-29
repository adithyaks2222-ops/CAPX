import platform
import psutil
from datetime import datetime
from typing import Any, Dict

from capx.core.collector.base import BaseCollector
from capx.logging_config import logger

class SystemCollector(BaseCollector):
    """Collects foundational Windows host telemetry and health facts."""
    
    def collect(self) -> Dict[str, Any]:
        logger.debug("Collecting host system facts...")
        
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = datetime.now().timestamp() - boot_time
            
            # Core OS facts
            os_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
            }
            
            # CPU facts
            cpu_info = {
                "physical_cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "usage_percent": psutil.cpu_percent(interval=1.0) # 1 sec block for accurate baseline
            }
            
            # Memory facts
            mem = psutil.virtual_memory()
            memory_info = {
                "total_bytes": mem.total,
                "available_bytes": mem.available,
                "used_bytes": mem.used,
                "usage_percent": mem.percent
            }
            
            # Disk facts (Targeting the primary system drive)
            partitions = psutil.disk_partitions()
            primary_mount = partitions[0].mountpoint if partitions else 'C:\\'
            disk = psutil.disk_usage(primary_mount)
            
            disk_info = {
                "mountpoint": primary_mount,
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "usage_percent": disk.percent
            }
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "uptime_seconds": round(uptime_seconds, 2),
                "os": os_info,
                "cpu": cpu_info,
                "memory": memory_info,
                "disk": disk_info
            }
            
        except Exception as e:
            logger.error(f"SystemCollector failed to gather OS facts: {e}")
            return {
                "status": "error",
                "message": str(e)
            }