"""Tests for the OpenCTI helper logic that doesn't need a live server.

`pycti` is stubbed so the module imports without the heavy dependency; we only
exercise the pure `_fmt_dt` timestamp formatter used for First/Last Seen.
"""
import sys
import types

# Stub pycti before importing the module (conftest already stubs validators/pyperclip).
if "pycti" not in sys.modules:
    m = types.ModuleType("pycti")
    m.OpenCTIApiClient = object
    sys.modules["pycti"] = m

import analyst_tool_opencti as o


def test_fmt_dt_trims_iso_timestamp():
    assert o._fmt_dt("2023-01-15T10:20:30.000Z") == "2023-01-15 10:20:30"
    assert o._fmt_dt("2024-12-31T23:59:59") == "2024-12-31 23:59:59"


def test_fmt_dt_handles_empty():
    assert o._fmt_dt(None) == "N/A"
    assert o._fmt_dt("") == "N/A"


def test_extract_common_fields_returns_nine_values():
    # First/last seen come from the STIX validity window, source from createdBy.
    results = [{
        "id": "abc-123",
        "revoked": False,
        "confidence": 80,
        "x_opencti_score": 90,
        "createdBy": {"name": "Analyst One"},
        "valid_from": "2023-01-15T10:20:30.000Z",
        "valid_until": "2023-06-01T00:00:00Z",
        "objectMarking": [{"definition": "AMBER"}],
        "objectLabel": [{"value": "apt"}],
    }]
    headers = "https://cti.example.com/graphql,TOKEN"
    fields = o._extract_common_fields(results, headers)
    assert len(fields) == 9
    link_url, source, active, confidence, score, tlp, keywords, first_seen, last_seen = fields
    assert source == "Analyst One"
    assert first_seen == "2023-01-15 10:20:30"
    assert last_seen == "2023-06-01 00:00:00"
    assert keywords == ["apt"]
