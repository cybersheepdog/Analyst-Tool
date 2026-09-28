"""Shared test setup.

Stubs the third-party packages the project imports at module load (but that the
unit tests don't actually need), so the pure-logic tests run without installing
the full heavy dependency stack. `requests` is used for real (it's light).
"""
import os
import sys
import types

# Make the project root importable.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _stub(name, **attrs):
    if name in sys.modules:
        return
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module


# analyst_tool_utilities imports these at load time.
_stub("validators", domain=lambda x: False, url=lambda x: False)
_stub("pyperclip", paste=lambda: "")

# The tool writes a diagnostics log (analyst_tool_log); keep the test suite
# from creating one in the repo.
os.environ.setdefault("ANALYST_TOOL_LOG", "")


import pytest


@pytest.fixture(autouse=True)
def _reset_circuit_breaker():
    """The per-service circuit breaker is process-wide state: a test that
    triggers a 429 would otherwise mute that service for later tests."""
    try:
        from analyst_tool_breaker import BREAKER
    except Exception:
        yield
        return
    BREAKER.reset()
    yield
    BREAKER.reset()
