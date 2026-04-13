"""Test fixtures for secfetch."""
import pytest


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
