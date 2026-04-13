"""Tests for secfetch logger module."""

import logging
import threading

import secfetch.core.logger as logger_module
from secfetch.core.logger import (
    get_logger,
    log_debug,
    log_error,
    log_info,
    log_warning,
    setup_logger,
)


class TestSetupLogger:
    def test_returns_logger_instance(self):
        logger = setup_logger("test_setup_unique_1")
        assert isinstance(logger, logging.Logger)

    def test_idempotent_no_duplicate_handlers(self):
        logger = setup_logger("test_setup_unique_2")
        handler_count = len(logger.handlers)
        setup_logger("test_setup_unique_2")
        assert len(logger.handlers) == handler_count

    def test_console_handler_level_is_warning(self):
        logger = setup_logger("test_setup_unique_3")
        stream_handlers = [
            h
            for h in logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]
        assert any(h.level == logging.WARNING for h in stream_handlers)

    def test_custom_level(self):
        logger = setup_logger("test_setup_unique_4", level="DEBUG")
        assert logger.level == logging.DEBUG


class TestGetLogger:
    def setup_method(self):
        logger_module._logger = None

    def teardown_method(self):
        logger_module._logger = None

    def test_returns_logger(self):
        assert isinstance(get_logger(), logging.Logger)

    def test_singleton_returns_same_object(self):
        l1 = get_logger()
        l2 = get_logger()
        assert l1 is l2

    def test_thread_safe_singleton(self):
        results = []

        def fetch():
            results.append(get_logger())

        threads = [threading.Thread(target=fetch) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(r is results[0] for r in results)


class TestLogFunctions:
    def setup_method(self):
        logger_module._logger = None

    def teardown_method(self):
        logger_module._logger = None

    def test_log_debug_calls_debug(self):
        logger = get_logger()
        called = []
        original = logger.debug
        logger.debug = lambda msg: called.append(("debug", msg))
        log_debug("test debug")
        logger.debug = original
        assert ("debug", "test debug") in called

    def test_log_info_calls_info(self):
        logger = get_logger()
        called = []
        original = logger.info
        logger.info = lambda msg: called.append(("info", msg))
        log_info("test info")
        logger.info = original
        assert ("info", "test info") in called

    def test_log_warning_calls_warning(self):
        logger = get_logger()
        called = []
        original = logger.warning
        logger.warning = lambda msg: called.append(("warning", msg))
        log_warning("test warning")
        logger.warning = original
        assert ("warning", "test warning") in called

    def test_log_error_calls_error(self):
        logger = get_logger()
        called = []
        original = logger.error
        logger.error = lambda msg: called.append(("error", msg))
        log_error("test error")
        logger.error = original
        assert ("error", "test error") in called
