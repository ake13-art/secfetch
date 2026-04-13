"""Standardized error handling for security checks."""
from __future__ import annotations

import functools
import subprocess
from typing import Any, Callable, Dict

from secfetch.core.logger import log_debug

SUBPROCESS_TIMEOUT: int = 5  # Default timeout in seconds for all subprocess calls


def handle_check_errors(func: Callable) -> Callable:
    """
    Decorator to provide consistent error handling for security checks.

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
        except Exception as e:
            # Don't expose internal exception details to users, but log for debugging
            log_debug(f"Unexpected error in {func.__name__}: {type(e).__name__}: {e}")
            return {"status": "info", "value": "check unavailable"}

    return wrapper


def safe_read_file(file_path: str, default: str | None = "not available") -> str | None:
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
    except (UnicodeDecodeError, OSError):
        return default


def safe_subprocess_run(
    cmd: list, timeout: int = SUBPROCESS_TIMEOUT, default: str = ""
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
    except OSError as e:
        result = subprocess.CompletedProcess(cmd, -1, default, f"error: {e}")
        return result


def sysctl_check(path: str, mapping: dict[str, tuple[str, str]]) -> dict[str, str]:
    """Read a sysctl value from *path* and translate via *mapping* to a status/value dict.

    Returns {"status": "info", "value": "not available"} if the path is unreadable
    or the value is not present in the mapping.
    """
    val = safe_read_file(path, default=None)
    if val is not None and val in mapping:
        return {"status": mapping[val][0], "value": mapping[val][1]}
    return {"status": "info", "value": "not available"}
