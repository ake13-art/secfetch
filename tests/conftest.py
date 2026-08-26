"""Test fixtures for secfetch."""
import logging

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


@pytest.fixture(autouse=True)
def _clean_fs_scan_cache():
    """Reset the module-level filesystem scan cache between tests."""
    try:
        from secfesc.checks.filesystem import permissions as perm_mod
    except ImportError:
        yield
        return
    saved = perm_mod._fs_scan_cache
    perm_mod._fs_scan_cache = None
    yield
    perm_mod._fs_scan_cache = saved


@pytest.fixture(autouse=True)
def _clean_port_db():
    """Snapshot and restore the port database between tests."""
    try:
        from secfesc.secfetch.data import port_db
    except ImportError:
        yield
        return
    with port_db._lock:
        saved = dict(port_db._port_db)
    yield
    with port_db._lock:
        port_db._port_db.clear()
        port_db._port_db.update(saved)


@pytest.fixture(autouse=True)
def _clean_logger():
    """Remove any handlers added to the secfesc logger and reset the module singleton."""
    from secfesc.shared import logger as logger_mod

    saved_singleton = logger_mod._logger
    py_logger = logging.getLogger("secfesc")
    saved_handlers = list(py_logger.handlers)
    saved_level = py_logger.level
    yield
    logger_mod._logger = saved_singleton
    for h in saved_handlers:
        if h not in py_logger.handlers:
            py_logger.addHandler(h)
    for h in list(py_logger.handlers):
        if h not in saved_handlers:
            h.close()
            py_logger.removeHandler(h)
    py_logger.setLevel(saved_level)


@pytest.fixture(autouse=True)
def _clean_check_registry():
    """Snapshot and restore the check registry between tests."""
    try:
        from secfesc.shared import registry as engine_module
    except ImportError:
        yield
        return
    with engine_module._registry_lock:
        saved = list(engine_module._checks)
    yield
    with engine_module._registry_lock:
        engine_module._checks.clear()
        engine_module._checks.extend(saved)
    with engine_module._discover_lock:
        engine_module._discovered = False
