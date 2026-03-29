"""
Professional logging system for secfetch
PROFESSIONALIZATION FIX: Added proper logging instead of unprofessional print() statements
"""

import logging
import sys
from pathlib import Path


def setup_logger(name: str = "secfetch", level: str = "INFO") -> logging.Logger:
    """
    Set up a professional logger with proper formatting and handlers.

    Args:
        name: Logger name (usually "secfetch")
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Avoid duplicate handlers if logger already configured
    if logger.handlers:
        return logger

    # Set log level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Create console handler for warnings and errors
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Create file handler for all logs (if possible)
    try:
        log_dir = Path.home() / ".config" / "secfetch"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "secfetch.log"

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    except (PermissionError, OSError):
        # If we can't write to log file, that's OK - just use console
        pass

    return logger


# Global logger instance
_logger = None


def get_logger() -> logging.Logger:
    """Get the global secfetch logger instance."""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger


def log_debug(message: str) -> None:
    """Log debug message."""
    get_logger().debug(message)


def log_info(message: str) -> None:
    """Log info message."""
    get_logger().info(message)


def log_warning(message: str) -> None:
    """Log warning message."""
    get_logger().warning(message)


def log_error(message: str) -> None:
    """Log error message."""
    get_logger().error(message)


def log_critical(message: str) -> None:
    """Log critical message."""
    get_logger().critical(message)
