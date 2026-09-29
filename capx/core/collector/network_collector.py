import psutil
from typing import Any, Dict, List
from capx.core.collector.base import BaseCollector
from capx.logging_config import logger

class NetworkCollector(BaseCollector):
    """Collects raw facts about active host network connections."""
    
    def collect(self) -> Dict[str, Any]:
        logger.debug("Collecting network connection facts...")
        connections: List[Dict[str, Any]] = []
        
        try:
            # kind='inet' grabs both IPv4 and IPv6
            net_conns = psutil.net_connections(kind='inet')
            
            for conn in net_conns:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                
                connections.append({
                    "fd": conn.fd,
                    "family": conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    "type": conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    "laddr": laddr,
                    "lport": conn.laddr.port if conn.laddr else None,
                    "raddr": raddr,
                    "rport": conn.raddr.port if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })
                
            return {
                "status": "success",
                "count": len(connections),
                "data": connections
            }
            
        except psutil.AccessDenied:
            logger.warning("Access Denied collecting network connections. Run as Administrator for full visibility.")
            return {
                "status": "partial",
                "message": "Access Denied. Run as Admin for full network mapping.",
                "count": 0,
                "data": []
            }
        except Exception as e:
            logger.error(f"NetworkCollector failed: {e}")
            return {
                "status": "error",
                "message": str(e)
            }