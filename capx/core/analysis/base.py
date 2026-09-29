from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseAnalyzer(ABC):
    """Abstract base class for all Analysis components."""
    
    @abstractmethod
    def analyze(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """Interprets raw collected facts and returns structured findings."""
        pass