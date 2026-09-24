"""
Upload content-type validation for source-code/plaintext extensions.
libmagic is replaced with a stub so results don't depend on its version.
Found in use: a .py file made mostly of embedded JS/JSX text was detected as
application/javascript and wrongly rejected.
"""

import sys
import types

import pytest

from app.services import document_service
from app.services.document_service import DocumentError, validate_content_type


@pytest.fixture
def detected(monkeypatch):
    box = {"mime": "text/plain"}
    fake = types.SimpleNamespace(from_buffer=lambda data, mime=True: box["mime"])
    monkeypatch.setitem(sys.modules, "magic", fake)
    return box


@pytest.mark.parametrize("mime", ["text/x-python", "text/plain", "application/javascript", "application/json"])
def test_plaintext_detections_are_accepted_for_source_files(detected, mime):
    detected["mime"] = mime
    assert validate_content_type(b"print('hi')", ".py") == mime


@pytest.mark.parametrize("mime", ["application/x-dosexec", "application/x-executable", "application/zip", "application/pdf"])
def test_binary_detections_are_still_rejected_for_source_files(detected, mime):
    detected["mime"] = mime
    with pytest.raises(DocumentError):
        validate_content_type(b"MZ\x90\x00", ".py")


def test_strict_extensions_do_not_gain_the_plaintext_allowance(detected):
    ext = next(iter(document_service.STRICT_MIME_TYPES))
    detected["mime"] = "application/javascript"
    with pytest.raises(DocumentError):
        validate_content_type(b"x", ext)
