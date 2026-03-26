"""
Test fixtures for secfetch
"""
import pytest
from unittest.mock import mock_open, patch, MagicMock


@pytest.fixture
def mock_proc_sys():
    """
    Fixture that mocks /proc/sys/* file reads.
    Usage:
        mock_proc_sys({"kernel.randomize_va_space": "2"})
    """
    def _mock_proc_sys(values: dict):
        def file_opener(path, *args, **kwargs):
            filename = path.split("/")[-1]
            if filename in values:
                return mock_open(read_data=values[filename])()
            raise FileNotFoundError(f"Mock file not found: {path}")
        return patch("builtins.open", side_effect=file_opener)
    return _mock_proc_sys


@pytest.fixture
def mock_subprocess_run():
    """
    Fixture that mocks subprocess.run calls.
    Usage:
        mock_subprocess({"ss": "output", "systemctl": "output"})
    """
    def _mock_subprocess(commands: dict):
        def run_effect(cmd, *args, **kwargs):
            cmd_str = cmd[0] if isinstance(cmd, list) else str(cmd)
            for key, value in commands.items():
                if key in cmd_str:
                    return MagicMock(
                        stdout=value,
                        stderr="",
                        returncode=0
                    )
            return MagicMock(stdout="", stderr="", returncode=1)
        return patch("subprocess.run", side_effect=run_effect)
    return _mock_subprocess


@pytest.fixture
def sample_results():
    """Sample security check results for testing."""
    return [
        {"name": "ASLR", "category": "kernel_security", "risk": "high", "status": "ok", "value": "Full"},
        {"name": "Secure Boot", "category": "system", "risk": "high", "status": "ok", "value": "Enabled"},
        {"name": "Firewall", "category": "network", "risk": "high", "status": "bad", "value": "No active firewall found"},
        {"name": "TCP SYN Cookies", "category": "network", "risk": "medium", "status": "warn", "value": "Disabled"},
    ]


@pytest.fixture
def all_ok_results():
    """All checks passing results."""
    return [
        {"name": "ASLR", "category": "kernel_security", "risk": "high", "status": "ok", "value": "Full"},
        {"name": "Secure Boot", "category": "system", "risk": "high", "status": "ok", "value": "Enabled"},
        {"name": "Firewall", "category": "network", "risk": "high", "status": "ok", "value": "ufw active"},
    ]


@pytest.fixture
def all_bad_results():
    """All checks failing results."""
    return [
        {"name": "ASLR", "category": "kernel_security", "risk": "high", "status": "bad", "value": "Disabled"},
        {"name": "Secure Boot", "category": "system", "risk": "high", "status": "bad", "value": "Disabled"},
        {"name": "Firewall", "category": "network", "risk": "high", "status": "bad", "value": "No active firewall found"},
    ]
