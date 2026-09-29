import logging
import logging.handlers
from capx.config import config

def setup_logging() -> logging.Logger:
    """Initialize structured, rotating file and console logging."""
    config.setup_directories()
    log_file = config.LOG_DIR / "capx.log"

    logger = logging.getLogger("capx")
    
    # Prevent duplicate handlers if called multiple times
    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.DEBUG if config.ENVIRONMENT == "development" else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - [%(levelname)s] - %(message)s"
    )

    # File Handler (5MB max, keep 3 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5*1024*1024, backupCount=3
    )
    file_handler.setFormatter(formatter)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()