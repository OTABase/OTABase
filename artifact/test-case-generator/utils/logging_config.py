import logging
import sys

# Flag to track if logging has been configured
_logging_configured = False


def setup_logging(level=logging.INFO, format_str='%(levelname)s - %(message)s') -> None:
    """
    Setup logging configuration. Can be called multiple times safely.
    
    Args:
        level: Logging level (default: logging.INFO)
        format_str: Format string for log messages
    """
    global _logging_configured
    
    # Configure logging - allow multiple calls but always ensure correct level
    root_logger = logging.getLogger()
    
    # Only add handler if none exists
    if not root_logger.handlers:
        logging.basicConfig(
            level=level,
            format=format_str,
            stream=sys.stdout
        )
    else:
        # Just update the level if handlers already exist
        root_logger.setLevel(level)
    
    _logging_configured = True


def ensure_info_level() -> None:
    """
    Ensure logging level is set to INFO, regardless of what other libraries do.
    Call this if you notice debug messages appearing unexpectedly.
    """
    logging.getLogger().setLevel(logging.INFO)


def is_debug() -> bool:
    """
    Returns True if the logging level is set to DEBUG

    Returns:
        bool: True if the logging level is set to DEBUG
    """
    return logging.getLogger().getEffectiveLevel() == logging.DEBUG


def reset_logging() -> None:
    """
    Reset logging configuration. Useful for testing.
    """
    global _logging_configured
    _logging_configured = False
