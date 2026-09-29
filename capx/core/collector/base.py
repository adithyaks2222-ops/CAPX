from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseCollector(ABC):
    """
    Abstract base class for all CAPX data collectors.
    Collectors are strictly responsible for gathering facts from the OS.
    They must never contain analysis, detection, or risk logic.
    """
    
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """
        Collect facts from the operating system.
        
        Returns:
            Dict[str, Any]: A dictionary containing a 'status' key 
            ('success' or 'error') and the collected factual data.
        """
        pass