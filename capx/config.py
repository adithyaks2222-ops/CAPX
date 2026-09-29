import os
from dataclasses import dataclass
from pathlib import Path

@dataclass
class AppConfig:
    """Centralized configuration for CAPX environments and parameters."""
    
    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    LOG_DIR: Path = BASE_DIR / "logs"
    REPORT_DIR: Path = BASE_DIR / "reports"
    DATA_DIR: Path = BASE_DIR / "data"
    
    # Environment
    ENVIRONMENT: str = os.getenv("CAPX_ENV", "production")
    
    # Risk Score Bands (System boundaries, not logic)
    RISK_SAFE_MAX: int = 25
    RISK_MONITOR_MAX: int = 50
    RISK_WARNING_MAX: int = 75
    # 76-100 is CRITICAL

    def setup_directories(self) -> None:
        """Ensure all required runtime directories exist."""
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)

config = AppConfig()