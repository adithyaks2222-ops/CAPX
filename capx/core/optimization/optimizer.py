import psutil
from typing import Dict
from capx.logging_config import logger

class SafeOptimizer:
    """Executes state-changing actions strictly bounded by safety rules."""
    
    def __init__(self):
        # Master blacklist of processes CAPX is forbidden from terminating
        self.critical_procs = {
            'svchost.exe', 'csrss.exe', 'wininit.exe', 'smss.exe', 
            'services.exe', 'explorer.exe', 'lsass.exe', 'winlogon.exe',
            'registry', 'system', 'system idle process'
        }

    def is_safe_to_terminate(self, pid: int, name: str) -> bool:
        """Safety Validation Step: Ensures the target is not a critical OS process."""
        if name.lower() in self.critical_procs:
            return False
        # PIDs 0-4 are reserved for the absolute core Windows kernel and System Idle Process
        if pid <= 4:
            return False
        return True

    def terminate_process(self, pid: int, name: str) -> Dict[str, str]:
        """Executes the termination and logs the audit trail."""
        if not self.is_safe_to_terminate(pid, name):
            logger.warning(f"BLOCKED: Attempted to terminate critical process {name}.")
            return {"status": "error", "message": f"Safety Violation: CAPX will not terminate critical OS process '{name}'."}
            
        try:
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=3) # Wait for graceful exit
            
            # Audit Log Requirement
            logger.info(f"AUDIT: Terminated process {name} (PID: {pid}) via explicit user authorization.")
            
            return {"status": "success", "message": f"Successfully terminated {name} (PID: {pid})."}
            
        except psutil.NoSuchProcess:
            return {"status": "error", "message": "Process no longer exists (it may have already closed)."}
        except psutil.AccessDenied:
            return {"status": "error", "message": "Access denied. Administrator privileges required."}
        except Exception as e:
            logger.error(f"Failed to terminate PID {pid}: {e}")
            return {"status": "error", "message": str(e)}