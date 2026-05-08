"""Local pytest configuration for backend tests.

Registers the ``asyncio`` marker so it does not trigger ``PytestUnknownMarkWarning``,
and provides a lightweight fallback runner if ``pytest-asyncio`` is unavailable
(minimal dev environments / CI shards that only need the pure-Python units).
"""
from __future__ import annotations

import asyncio
import inspect

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "asyncio: mark test as async (runs via event loop fallback if pytest-asyncio absent)",
    )


try:
    import pytest_asyncio
    _HAS_PYTEST_ASYNCIO = True
except Exception:
    _HAS_PYTEST_ASYNCIO = False


if not _HAS_PYTEST_ASYNCIO:
    @pytest.hookimpl(tryfirst=True)
    def pytest_pyfunc_call(pyfuncitem):
        func = pyfuncitem.obj
        if not inspect.iscoroutinefunction(func):
            return None
        sig = inspect.signature(func)
        kwargs = {
            name: pyfuncitem.funcargs[name]
            for name in sig.parameters
            if name in pyfuncitem.funcargs
        }
        asyncio.run(func(**kwargs))
        return True
