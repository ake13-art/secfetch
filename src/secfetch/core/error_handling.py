"""
Standardized error handling for security checks
ERROR HANDLING FIX: Created consistent error handling patterns across all checks
"""

import functools
import subprocess
from typing import Any, Callable, Dict


def handle_check_errors(func: Callable) -> Callable:
    """
    Decorator to provide consistent error handling for security checks.

    PROFESSIONALIZATION FIX: Standardizes error handling across all security checks
    to ensure consistent user experience and professional error messages.

    Returns consistent error responses:
    - "not available" for missing files/permissions
    - "scan timeout" for operation timeouts
    - "check unavailable" for unexpected errors
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            return func(*args, **kwargs)
        except (FileNotFoundError, PermissionError):
            return {"status": "info", "value": "not available"}
        except subprocess.TimeoutExpired:
            return {"status": "info", "value": "scan timeout"}
        except subprocess.CalledProcessError:
            return {"status": "info", "value": "check unavailable"}
        except Exception:
            # Don't expose internal exception details to users
            return {"status": "info", "value": "check unavailable"}

    return wrapper


def safe_read_file(file_path: str, default: str = "not available") -> str:
    """
    Safely read a file with consistent error handling.

    Args:
        file_path: Path to file to read
        default: Default value if file cannot be read

    Returns:
        File contents (stripped) or default value
    """
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return default
    except Exception:
        return default


def safe_subprocess_run(
    cmd: list, timeout: int = 5, default: str = ""
) -> subprocess.CompletedProcess:
    """
    Safely run subprocess with consistent error handling.

    Args:
        cmd: Command to run as list
        timeout: Timeout in seconds
        default: Default stdout on error

    Returns:
        CompletedProcess with consistent error handling
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Don't raise on non-zero exit codes
        )
    except subprocess.TimeoutExpired:
        # Return a fake result that indicates timeout
        result = subprocess.CompletedProcess(cmd, -1, default, "timeout")
        return result
    except FileNotFoundError:
        # Return a fake result that indicates command not found
        result = subprocess.CompletedProcess(cmd, -1, default, "command not found")
        return result
    except Exception:
        # Return a fake result that indicates generic error
        result = subprocess.CompletedProcess(cmd, -1, default, "error")
        return result


def standardize_status_value(value: str) -> str:
    """
    Standardize status values to consistent, user-friendly messages.

    PROFESSIONALIZATION FIX: Ensures all error messages are consistent and professional.
    """
    # Common mappings for standardization
    mappings = {
        "Unknown": "not available",
        "Error": "check unavailable",
        "Failed": "check unavailable",
        "N/A": "not available",
        "": "not available",
    }

    # Remove "Error: " prefixes
    if value.startswith("Error: "):
        value = value[7:]  # Remove "Error: " prefix
        return "check unavailable"

    return mappings.get(value, value)
